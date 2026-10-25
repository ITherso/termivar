//! Original, transport-free proof fixtures. These are not captured provider output.
use super::*;
use sha2::{Digest, Sha256};

fn policy() -> SuppliedSessionPolicy {
    SuppliedSessionPolicy::parse_toml(
        &url::Url::parse("http://127.0.0.1:18080/").unwrap(),
        br#"
schema = "security.supplied-session-policy/v6"
principal_alias = "owned-proof-principal"
credential_mechanism = "authorization_header"
credential_acquisition = "imported_oauth_code_pkce"
health_path = "/health"
health_json_field = "authenticated"
resources = ["/one", "/two"]
max_session_requests = 8
max_total_response_bytes = 65536
max_response_body_bytes = 8192
max_wall_time_ms = 5000
[oauth_code]
profile = "external-public-code-s256-bearer/v1"
transport_profile = "owned-numeric-loopback-http/v1"
issuer = "http://127.0.0.1:18081/issuer"
token_endpoint = "http://127.0.0.1:18081/issuer/token"
client_id = "owned-proof-public"
redirect_uri = "http://127.0.0.1:18080/callback"
scopes = ["canary-read"]
max_token_response_bytes = 8192
[oauth_refresh]
profile = "scheduled-public-bearer-refresh/v1"
after_resource_count = 1
max_attempts = 1
"#,
    )
    .unwrap()
}

fn boundary(
    knowledge: &KnowledgeBase,
    policy: &SuppliedSessionPolicy,
    label: &str,
) -> BoundaryEvidence {
    let reference = super::super::commit_value_safe_evidence(
        policy,
        label,
        b"security.synthetic.refresh-boundary-fixture.v1\0",
        "synthetic-boundary-sha256",
        "synthetic-boundary",
        "original-synthetic-boundary",
        label.to_owned(),
        knowledge,
    )
    .unwrap();
    let id = EvidenceId::parse(&reference).unwrap();
    BoundaryEvidence {
        reference,
        expected: knowledge.inspect_evidence(&id, Clone::clone).unwrap(),
    }
}

fn fixture() -> (
    SuppliedSessionPolicy,
    KnowledgeBase,
    CommittedOAuthCodeReceipt,
    CommittedOAuthRefreshReceipt,
) {
    let policy = policy();
    let knowledge = KnowledgeBase::new();
    let code = super::super::oauth_code::tests::synthetic_refresh_code_receipt(&policy, &knowledge);
    let resource = boundary(&knowledge, &policy, "resource");
    let health = boundary(&knowledge, &policy, "health");
    let idp = policy.oauth_code_policy().unwrap();
    let refresh = policy.oauth_refresh_policy().unwrap();
    // Independent literal framing. Do not call credential_binding to create its oracle.
    let literal = format!(
        "policy={};application={};idp={};refresh_policy={};purpose=oauth_refresh;prior_credential={};boundary_resource={};boundary_health={};initial_epoch=1;final_epoch=2;status=200;body_state=complete;response_bytes=174;scope=exact_supported_echo;declared_lifetime=180;replacement_value_differs=true;revocation=not_established;outcome=credential_committed",
        policy.policy_reference(),policy.application_reference(),idp.binding_reference(),refresh.binding_reference(),
        code.evidence_reference(),resource.reference,health.reference);
    let reference = super::super::commit_value_safe_evidence(
        &policy,
        refresh.binding_reference(),
        b"security.supplied-session-oauth-refresh-evidence.v1\0",
        "supplied-session-oauth-refresh-evidence-sha256",
        "oauth-refresh-credential-committed",
        "descriptor-bound-scheduled-oauth-refresh",
        literal,
        &knowledge,
    )
    .unwrap();
    let id = EvidenceId::parse(&reference).unwrap();
    let receipt = CommittedOAuthRefreshReceipt {
        knowledge_authority: knowledge.authority().clone(),
        policy_reference: policy.policy_reference().to_owned(),
        application_reference: policy.application_reference().to_owned(),
        idp_reference: idp.binding_reference().to_owned(),
        refresh_reference: refresh.binding_reference().to_owned(),
        principal_alias: policy.principal_alias().to_owned(),
        prior_credential_reference: code.evidence_reference().to_owned(),
        resource,
        health,
        evidence_reference: reference,
        expected_evidence: knowledge.inspect_evidence(&id, Clone::clone).unwrap(),
        response_bytes: 174,
        declared_lifetime_seconds: 180,
    };
    (policy, knowledge, code, receipt)
}

#[test]
fn refresh_receipt_preserves_original_timestamp_but_rejects_other_knowledge_authority() {
    let (policy, knowledge, code, receipt) = fixture();
    std::thread::sleep(Duration::from_millis(3));
    assert!(receipt.is_valid_for(&policy, &code, &knowledge));
    assert!(receipt.is_valid_for(&policy, &code, &knowledge.clone()));
    let foreign = KnowledgeBase::new();
    for reference in [
        code.evidence_reference(),
        &receipt.resource.reference,
        &receipt.health.reference,
        &receipt.evidence_reference,
    ] {
        let id = EvidenceId::parse(reference).unwrap();
        foreign
            .insert_evidence(knowledge.inspect_evidence(&id, Clone::clone).unwrap())
            .unwrap();
    }
    assert!(
        !receipt.is_valid_for(&policy, &code, &foreign),
        "copied public records are not private authority"
    );
}

#[test]
fn refresh_receipt_rejects_paired_unrelated_record_and_reference_substitution() {
    let (policy, knowledge, code, mut receipt) = fixture();
    assert!(receipt.is_valid_for(&policy, &code, &knowledge));
    let id = EvidenceId::parse(code.evidence_reference()).unwrap();
    receipt.evidence_reference = code.evidence_reference().to_owned();
    receipt.expected_evidence = knowledge.inspect_evidence(&id, Clone::clone).unwrap();
    assert!(
        !receipt.is_valid_for(&policy, &code, &knowledge),
        "same-KB code evidence is not the separately committed renewal evidence"
    );
}

#[test]
fn refresh_receipt_rejects_context_boundary_and_accounting_mutations() {
    let mutations: &[fn(&mut CommittedOAuthRefreshReceipt)] = &[
        |r| r.policy_reference.push('x'),
        |r| r.application_reference.push('x'),
        |r| r.idp_reference.push('x'),
        |r| r.refresh_reference.push('x'),
        |r| r.principal_alias.push('x'),
        |r| r.prior_credential_reference.push('x'),
        |r| r.resource.reference.push('x'),
        |r| r.health.reference.push('x'),
        |r| r.response_bytes = 0,
        |r| r.response_bytes = 175,
        |r| r.declared_lifetime_seconds = 0,
        |r| r.declared_lifetime_seconds = 181,
        |r| r.evidence_reference.push('x'),
    ];
    assert_eq!(mutations.len(), 13);
    for (index, mutate) in mutations.iter().enumerate() {
        let (policy, knowledge, code, mut receipt) = fixture();
        assert!(receipt.is_valid_for(&policy, &code, &knowledge));
        mutate(&mut receipt);
        assert!(
            !receipt.is_valid_for(&policy, &code, &knowledge),
            "proof mutation {index}"
        );
    }
}

#[test]
fn boundary_read_requires_exact_subject_source_kind_predicate_value_and_reliability() {
    let policy = policy();
    let binding = "original synthetic value-free boundary";
    let mut digest = Sha256::new();
    digest.update(b"security.synthetic.boundary-read.v1\0");
    digest.update(binding.as_bytes());
    let reference = format!("synthetic-boundary-sha256:{:x}", digest.finalize());
    for mutation in 0..7 {
        let knowledge = KnowledgeBase::new();
        let expected = Evidence::with_id_at(
            EvidenceId::parse(&reference).unwrap(),
            EntityId::new(if mutation == 1 {
                "different-application"
            } else {
                policy.application_reference()
            })
            .unwrap(),
            if mutation == 2 {
                EvidenceKind::Http
            } else {
                EvidenceKind::Authentication
            },
            KnowledgePredicate::new(
                RESOURCE_COMMIT_EVIDENCE_NAMESPACE,
                if mutation == 3 {
                    "different-predicate"
                } else {
                    "original-predicate"
                },
            )
            .unwrap(),
            EvidenceValue::Text(
                if mutation == 4 {
                    "different-value"
                } else {
                    binding
                }
                .to_owned(),
            ),
            EvidenceSource::new(
                super::super::RESOURCE_COMMIT_EVIDENCE_COMPONENT,
                if mutation == 5 {
                    "different-method"
                } else {
                    "original-method"
                },
            )
            .unwrap()
            .with_correlation_id("original-correlation")
            .unwrap(),
            if mutation == 6 {
                ConfidenceScore::NONE
            } else {
                ConfidenceScore::MAX
            },
            42,
        );
        knowledge.insert_evidence(expected).unwrap();
        assert_eq!(
            BoundaryEvidence::read(
                &policy,
                &knowledge,
                &reference,
                b"security.synthetic.boundary-read.v1\0",
                "synthetic-boundary-sha256",
                "original-predicate",
                "original-method",
                "original-correlation",
                binding.to_owned()
            )
            .is_some(),
            mutation == 0,
            "exact evidence reconstruction mutation {mutation}"
        );
    }
}
