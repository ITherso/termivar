//! Deterministic entity extraction rules mapping evidence to semantic entities.

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use venom_core::{EntityId, Evidence, EvidenceKind, EvidenceValue};

use crate::knowledge::KnowledgeSnapshot;
use crate::semantic::entity::{AuthArtifactKind, SemanticEntity, SemanticEntityType};

/// Version prefix for canonical entity identifiers.
const CANONICAL_ID_VERSION: &str = "v1";

/// Header allowlist for un-redacted metadata extraction.
const ALLOWED_HEADERS: &[&str] = &[
    "content-type",
    "server",
    "location",
    "www-authenticate",
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "x-powered-by",
];

/// Deterministic engine extracting strongly-typed semantic entities from scanner evidence.
#[derive(Debug, Clone, Default)]
pub struct EntityExtractor;

impl EntityExtractor {
    /// Creates a new entity extractor instance.
    pub fn new() -> Self {
        Self
    }

    /// Extracts entities from a knowledge snapshot.
    pub fn extract_from_snapshot(&self, snapshot: &KnowledgeSnapshot) -> Vec<SemanticEntity> {
        self.extract_from_evidence(snapshot.evidence())
    }

    /// Extracts entities deterministically from a slice of evidence records.
    pub fn extract_from_evidence(&self, evidence_list: &[Evidence]) -> Vec<SemanticEntity> {
        let mut entity_map = BTreeMap::<EntityId, SemanticEntity>::new();

        for evidence in evidence_list {
            if let Some(extracted) = self.project_evidence(evidence) {
                entity_map
                    .entry(extracted.id().clone())
                    .and_modify(|existing| {
                        let mut merged_attrs = existing.attributes().clone();
                        for (key, values) in extracted.attributes() {
                            merged_attrs
                                .entry(key.clone())
                                .or_default()
                                .extend(values.iter().cloned());
                        }
                        let mut merged_sources = existing.source_evidence_ids().to_vec();
                        merged_sources.extend(extracted.source_evidence_ids().iter().cloned());
                        *existing = SemanticEntity::new(
                            existing.id().clone(),
                            existing.entity_type(),
                            merged_attrs,
                            merged_sources,
                        );
                    })
                    .or_insert(extracted);
            }
        }

        entity_map.into_values().collect()
    }

    fn project_evidence(&self, evidence: &Evidence) -> Option<SemanticEntity> {
        let predicate_name = evidence.predicate().name();

        let val_str = match evidence.value() {
            EvidenceValue::Text(s) => s.as_str(),
            _ => return None,
        };

        match (evidence.kind(), predicate_name) {
            (EvidenceKind::Technology, _) => {
                let name = val_str.trim();
                if name.is_empty() {
                    return None;
                }
                let canonical_id = EntityId::new(format!(
                    "{CANONICAL_ID_VERSION}:tech:{}",
                    name.to_lowercase()
                ))
                .ok()?;
                let mut attrs = BTreeMap::new();
                attrs.insert("name".to_string(), BTreeSet::from([name.to_string()]));

                Some(SemanticEntity::new(
                    canonical_id,
                    SemanticEntityType::Technology,
                    attrs,
                    vec![evidence.id().clone()],
                ))
            },
            (EvidenceKind::Http | EvidenceKind::Network, "endpoint" | "path" | "route" | "url") => {
                let (canonical_id, url_str, method) =
                    parse_canonical_endpoint(evidence.subject().as_str(), val_str)?;
                let mut attrs = BTreeMap::new();
                attrs.insert("url".to_string(), BTreeSet::from([url_str]));
                if let Some(method) = method {
                    attrs.insert("method".to_string(), BTreeSet::from([method]));
                }

                Some(SemanticEntity::new(
                    canonical_id,
                    SemanticEntityType::Endpoint,
                    attrs,
                    vec![evidence.id().clone()],
                ))
            },
            (EvidenceKind::Dns | EvidenceKind::Network, "domain" | "hostname" | "host" | "ip") => {
                let raw_val = val_str.trim();
                if raw_val.is_empty() {
                    return None;
                }
                if let Some(canonical_ip) = normalize_ip_address(raw_val) {
                    let canonical_id =
                        EntityId::new(format!("{CANONICAL_ID_VERSION}:ip:{canonical_ip}")).ok()?;
                    let mut attrs = BTreeMap::new();
                    attrs.insert("ip".to_string(), BTreeSet::from([canonical_ip]));
                    Some(SemanticEntity::new(
                        canonical_id,
                        SemanticEntityType::IpAddress,
                        attrs,
                        vec![evidence.id().clone()],
                    ))
                } else {
                    let lower_domain = raw_val.to_lowercase();
                    let canonical_id =
                        EntityId::new(format!("{CANONICAL_ID_VERSION}:domain:{lower_domain}"))
                            .ok()?;
                    let mut attrs = BTreeMap::new();
                    attrs.insert("domain".to_string(), BTreeSet::from([lower_domain]));
                    Some(SemanticEntity::new(
                        canonical_id,
                        SemanticEntityType::Domain,
                        attrs,
                        vec![evidence.id().clone()],
                    ))
                }
            },
            (EvidenceKind::Authentication, "token" | "jwt" | "bearer" | "cookie" | "api_key") => {
                // REDACTION GUARANTEE: Never store raw token in attributes
                let raw_token = val_str.trim();
                if raw_token.is_empty() {
                    return None;
                }

                let kind = classify_auth_kind(predicate_name, raw_token);
                let fingerprint = hash_token(kind, raw_token);
                let canonical_id = EntityId::new(format!(
                    "{CANONICAL_ID_VERSION}:auth_artifact:{fingerprint}"
                ))
                .ok()?;

                let mut attrs = BTreeMap::new();
                attrs.insert(
                    "auth_kind".to_string(),
                    BTreeSet::from([format!("{kind:?}")]),
                );
                attrs.insert("fingerprint".to_string(), BTreeSet::from([fingerprint]));
                attrs.insert(
                    "length".to_string(),
                    BTreeSet::from([raw_token.len().to_string()]),
                );

                Some(SemanticEntity::new(
                    canonical_id,
                    SemanticEntityType::AuthArtifact,
                    attrs,
                    vec![evidence.id().clone()],
                ))
            },
            (EvidenceKind::Http, "header") => {
                let (header_name, header_value) = parse_header_pair(val_str)?;
                let name_lower = header_name.to_lowercase();
                if name_lower.is_empty() {
                    return None;
                }

                let canonical_id =
                    EntityId::new(format!("{CANONICAL_ID_VERSION}:header:{name_lower}")).ok()?;
                let mut attrs = BTreeMap::new();
                attrs.insert("name".to_string(), BTreeSet::from([name_lower.clone()]));

                let safe_val = if ALLOWED_HEADERS.contains(&name_lower.as_str()) {
                    header_value
                } else {
                    "[REDACTED]".to_string()
                };
                attrs.insert("value".to_string(), BTreeSet::from([safe_val]));

                Some(SemanticEntity::new(
                    canonical_id,
                    SemanticEntityType::Header,
                    attrs,
                    vec![evidence.id().clone()],
                ))
            },
            _ => {
                let subj = evidence.subject().as_str().trim();
                if subj.is_empty() {
                    return None;
                }
                let canonical_id =
                    EntityId::new(format!("{CANONICAL_ID_VERSION}:subject:{subj}")).ok()?;
                let mut attrs = BTreeMap::new();
                attrs.insert(
                    predicate_name.to_string(),
                    BTreeSet::from([val_str.to_string()]),
                );

                Some(SemanticEntity::new(
                    canonical_id,
                    SemanticEntityType::Endpoint,
                    attrs,
                    vec![evidence.id().clone()],
                ))
            },
        }
    }
}

fn normalize_ip_address(s: &str) -> Option<String> {
    let s = s.trim();
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.chars().all(|c| c.is_ascii_digit())
                && p.parse::<u16>().is_ok_and(|n| n <= 255)
        })
    {
        return Some(s.to_string());
    }

    // IPv6 normalization check
    if s.contains(':') && s.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
        let clean = s.to_lowercase();
        return Some(clean);
    }

    None
}

fn hash_token(kind: AuthArtifactKind, raw_token: &str) -> String {
    let mut hasher = Sha256::new();
    let domain_sep = format!("venom:auth-artifact:{CANONICAL_ID_VERSION}:{kind:?}:{raw_token}");
    hasher.update(domain_sep.as_bytes());
    let result = hasher.finalize();
    result.iter().map(|b| format!("{b:02x}")).collect()
}

fn classify_auth_kind(predicate: &str, raw: &str) -> AuthArtifactKind {
    if predicate == "cookie" {
        return AuthArtifactKind::SessionCookie;
    }
    if predicate == "api_key" {
        return AuthArtifactKind::ApiKey;
    }

    // Strict JWT base64url segment check (A-Z, a-z, 0-9, -, _). Reject +, /, or =.
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
    {
        return AuthArtifactKind::Jwt;
    }

    if predicate == "bearer" || raw.to_lowercase().starts_with("bearer ") {
        return AuthArtifactKind::BearerToken;
    }

    AuthArtifactKind::Unknown
}

fn parse_header_pair(raw: &str) -> Option<(String, String)> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Some((k, v)) = raw.split_once(':') {
        Some((k.trim().to_string(), v.trim().to_string()))
    } else {
        Some((raw.trim().to_string(), String::new()))
    }
}

fn parse_canonical_endpoint(
    subject_str: &str,
    val_str: &str,
) -> Option<(EntityId, String, Option<String>)> {
    let raw = if val_str.to_lowercase().starts_with("http://")
        || val_str.to_lowercase().starts_with("https://")
    {
        val_str
    } else {
        subject_str
    };

    let target = raw.strip_prefix("endpoint:").unwrap_or(raw);

    let (url_part, method_part) = if let Some((u, m)) = target.split_once('#') {
        (u, Some(m.to_uppercase()))
    } else {
        (target, None)
    };

    let url_without_query = if let Some((base, _query)) = url_part.split_once('?') {
        base
    } else {
        url_part
    };

    let (scheme, rest) = if let Some((s, r)) = url_without_query.split_once("://") {
        (s.to_lowercase(), r)
    } else {
        ("http".to_string(), url_without_query)
    };

    let (host_port, path) = if let Some((hp, p)) = rest.split_once('/') {
        (hp, format!("/{p}"))
    } else {
        (rest, "/".to_string())
    };

    let host_port_lower = host_port.to_lowercase();
    let normalized_hp = if scheme == "http" && host_port_lower.ends_with(":80") {
        host_port_lower.trim_end_matches(":80").to_string()
    } else if scheme == "https" && host_port_lower.ends_with(":443") {
        host_port_lower.trim_end_matches(":443").to_string()
    } else {
        host_port_lower
    };

    let normalized_url = format!("{scheme}://{normalized_hp}{path}");
    let method_suffix = method_part.as_deref().unwrap_or("GET");
    let canonical_str = format!("{CANONICAL_ID_VERSION}:endpoint:{normalized_url}#{method_suffix}");
    let canonical_id = EntityId::new(canonical_str).ok()?;

    Some((canonical_id, normalized_url, method_part))
}

#[cfg(test)]
mod tests {
    use super::*;
    use venom_core::{
        ConfidenceScore, EvidenceKind, EvidenceSource, EvidenceValue, KnowledgePredicate,
    };

    fn subject() -> EntityId {
        EntityId::new("endpoint:https://example.test/api/user").unwrap()
    }

    #[test]
    fn canonical_ids_are_lowercase_where_required() {
        let ev = Evidence::new(
            EntityId::new("endpoint:HTTPS://EXAMPLE.TEST:443/API/USER").unwrap(),
            EvidenceKind::Http,
            KnowledgePredicate::new("http", "endpoint").unwrap(),
            EvidenceValue::Text("HTTPS://EXAMPLE.TEST:443/API/USER".into()),
            EvidenceSource::new("scanner", "test").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let extractor = EntityExtractor::new();
        let entities = extractor.extract_from_evidence(&[ev]);
        assert_eq!(entities.len(), 1);
        assert_eq!(
            entities[0].id().as_str(),
            "v1:endpoint:https://example.test/API/USER#GET"
        );
    }

    #[test]
    fn default_ports_are_normalized() {
        let ev_http = Evidence::new(
            EntityId::new("endpoint:http://example.test:80/api").unwrap(),
            EvidenceKind::Http,
            KnowledgePredicate::new("http", "endpoint").unwrap(),
            EvidenceValue::Text("http://example.test:80/api".into()),
            EvidenceSource::new("scanner", "test").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let ev_https = Evidence::new(
            EntityId::new("endpoint:https://example.test:443/api").unwrap(),
            EvidenceKind::Http,
            KnowledgePredicate::new("http", "endpoint").unwrap(),
            EvidenceValue::Text("https://example.test:443/api".into()),
            EvidenceSource::new("scanner", "test").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let extractor = EntityExtractor::new();
        let entities = extractor.extract_from_evidence(&[ev_http, ev_https]);

        assert_eq!(
            entities[0].id().as_str(),
            "v1:endpoint:http://example.test/api#GET"
        );
        assert_eq!(
            entities[1].id().as_str(),
            "v1:endpoint:https://example.test/api#GET"
        );
    }

    #[test]
    fn ipv6_ids_use_one_canonical_representation() {
        let ev = Evidence::new(
            subject(),
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "ip").unwrap(),
            EvidenceValue::Text("2001:0DB8:85A3:0000:0000:8A2E:0370:7334".into()),
            EvidenceSource::new("scanner", "dns").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let extractor = EntityExtractor::new();
        let entities = extractor.extract_from_evidence(&[ev]);
        assert_eq!(
            entities[0].id().as_str(),
            "v1:ip:2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        );
    }

    #[test]
    fn path_normalization_does_not_collapse_distinct_resources() {
        let ev1 = Evidence::new(
            subject(),
            EvidenceKind::Http,
            KnowledgePredicate::new("http", "endpoint").unwrap(),
            EvidenceValue::Text("https://example.test/api/user".into()),
            EvidenceSource::new("scanner", "test").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let ev2 = Evidence::new(
            subject(),
            EvidenceKind::Http,
            KnowledgePredicate::new("http", "endpoint").unwrap(),
            EvidenceValue::Text("https://example.test/api/users".into()),
            EvidenceSource::new("scanner", "test").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let extractor = EntityExtractor::new();
        let entities = extractor.extract_from_evidence(&[ev1, ev2]);
        assert_eq!(entities.len(), 2);
        assert_ne!(entities[0].id(), entities[1].id());
    }

    #[test]
    fn jwt_detection_rejects_invalid_base64url_segments() {
        // Contains '+' which is standard base64 but invalid base64url for JWT
        let invalid_jwt = "eyJhbGciOiJIUzI1Ni+";
        let ev = Evidence::new(
            subject(),
            EvidenceKind::Authentication,
            KnowledgePredicate::new("authentication", "bearer").unwrap(),
            EvidenceValue::Text(invalid_jwt.into()),
            EvidenceSource::new("scanner", "header").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let extractor = EntityExtractor::new();
        let entities = extractor.extract_from_evidence(&[ev]);
        assert_eq!(
            entities[0]
                .attributes()
                .get("auth_kind")
                .unwrap()
                .iter()
                .next()
                .unwrap(),
            "BearerToken"
        );
    }

    #[test]
    fn fingerprint_is_domain_separated_by_artifact_kind() {
        let raw_token = "secret123";
        let fp_bearer = hash_token(AuthArtifactKind::BearerToken, raw_token);
        let fp_cookie = hash_token(AuthArtifactKind::SessionCookie, raw_token);

        assert_ne!(fp_bearer, fp_cookie);
    }

    #[test]
    fn empty_or_malformed_evidence_produces_no_entity() {
        let ev_empty = Evidence::new(
            subject(),
            EvidenceKind::Technology,
            KnowledgePredicate::new("technology", "framework").unwrap(),
            EvidenceValue::Text("   ".into()),
            EvidenceSource::new("scanner", "test").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let extractor = EntityExtractor::new();
        let entities = extractor.extract_from_evidence(&[ev_empty]);
        assert!(entities.is_empty());
    }

    #[test]
    fn same_input_serializes_byte_for_byte_identically() {
        let ev1 = Evidence::new(
            subject(),
            EvidenceKind::Technology,
            KnowledgePredicate::new("technology", "framework").unwrap(),
            EvidenceValue::Text("Laravel".into()),
            EvidenceSource::new("scanner", "h1").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let ev2 = Evidence::new(
            subject(),
            EvidenceKind::Technology,
            KnowledgePredicate::new("technology", "framework").unwrap(),
            EvidenceValue::Text("Symfony".into()),
            EvidenceSource::new("scanner", "h2").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let extractor = EntityExtractor::new();
        let e1 = &extractor.extract_from_evidence(&[ev1.clone(), ev2.clone()])[0];
        let e2 = &extractor.extract_from_evidence(&[ev2, ev1])[0];

        let bytes1 = serde_json::to_vec(e1).unwrap();
        let bytes2 = serde_json::to_vec(e2).unwrap();

        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn raw_tokens_never_appear_in_entity_attributes_or_debug() {
        let secret_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        let ev = Evidence::new(
            subject(),
            EvidenceKind::Authentication,
            KnowledgePredicate::new("authentication", "jwt").unwrap(),
            EvidenceValue::Text(secret_jwt.into()),
            EvidenceSource::new("scanner", "header").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let extractor = EntityExtractor::new();
        let entities = extractor.extract_from_evidence(&[ev]);

        assert_eq!(entities.len(), 1);
        let entity = &entities[0];

        let debug_output = format!("{entity:?}");
        assert!(
            !debug_output.contains(secret_jwt),
            "Raw secret token leaked into Debug representation!"
        );

        for values in entity.attributes().values() {
            for v in values {
                assert!(
                    !v.contains(secret_jwt),
                    "Raw secret token stored in entity attributes!"
                );
            }
        }

        assert_eq!(
            entity
                .attributes()
                .get("auth_kind")
                .unwrap()
                .iter()
                .next()
                .unwrap(),
            "Jwt"
        );
        assert!(entity.attributes().contains_key("fingerprint"));
        assert_eq!(
            entity
                .attributes()
                .get("length")
                .unwrap()
                .iter()
                .next()
                .unwrap(),
            &secret_jwt.len().to_string()
        );
    }

    #[test]
    fn sensitive_header_values_are_redacted() {
        let ev1 = Evidence::new(
            subject(),
            EvidenceKind::Http,
            KnowledgePredicate::new("http", "header").unwrap(),
            EvidenceValue::Text("Authorization: Bearer secret123".into()),
            EvidenceSource::new("scanner", "header").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let ev2 = Evidence::new(
            subject(),
            EvidenceKind::Http,
            KnowledgePredicate::new("http", "header").unwrap(),
            EvidenceValue::Text("Content-Type: application/json".into()),
            EvidenceSource::new("scanner", "header").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let extractor = EntityExtractor::new();
        let entities = extractor.extract_from_evidence(&[ev1, ev2]);

        let auth_hdr = entities
            .iter()
            .find(|e| {
                e.attributes()
                    .get("name")
                    .unwrap()
                    .contains("authorization")
            })
            .unwrap();
        assert_eq!(
            auth_hdr
                .attributes()
                .get("value")
                .unwrap()
                .iter()
                .next()
                .unwrap(),
            "[REDACTED]"
        );

        let ct_hdr = entities
            .iter()
            .find(|e| e.attributes().get("name").unwrap().contains("content-type"))
            .unwrap();
        assert_eq!(
            ct_hdr
                .attributes()
                .get("value")
                .unwrap()
                .iter()
                .next()
                .unwrap(),
            "application/json"
        );
    }

    #[test]
    fn duplicate_evidence_ids_are_removed() {
        let ev1 = Evidence::new(
            subject(),
            EvidenceKind::Technology,
            KnowledgePredicate::new("technology", "framework").unwrap(),
            EvidenceValue::Text("Laravel".into()),
            EvidenceSource::new("scanner", "h1").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let extractor = EntityExtractor::new();
        let entities = extractor.extract_from_evidence(&[ev1.clone(), ev1.clone()]);

        assert_eq!(entities[0].source_evidence_ids().len(), 1);
        assert_eq!(entities[0].source_evidence_ids()[0], *ev1.id());
    }

    #[test]
    fn separates_domain_and_ip_address_entities() {
        let ev_domain = Evidence::new(
            subject(),
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "domain").unwrap(),
            EvidenceValue::Text("example.test".into()),
            EvidenceSource::new("scanner", "dns").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let ev_ip = Evidence::new(
            subject(),
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "ip").unwrap(),
            EvidenceValue::Text("192.0.2.10".into()),
            EvidenceSource::new("scanner", "dns").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let extractor = EntityExtractor::new();
        let entities = extractor.extract_from_evidence(&[ev_domain, ev_ip]);

        assert_eq!(entities.len(), 2);
        assert!(entities
            .iter()
            .any(|e| e.entity_type() == SemanticEntityType::Domain));
        assert!(entities
            .iter()
            .any(|e| e.entity_type() == SemanticEntityType::IpAddress));
    }
}
