//! Deterministic entity extraction rules mapping evidence to semantic entities.

use base64::Engine;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use url::Url;
use venom_core::{EntityId, Evidence, EvidenceKind, EvidenceValue};

use crate::knowledge::KnowledgeSnapshot;
use crate::semantic::entity::{
    AuthArtifactKind, SemanticEntity, SemanticEntityType, SemanticExtractionLimits,
};

/// Version prefix for canonical entity identifiers.
const CANONICAL_ID_VERSION: &str = "v1";

/// Deterministic engine extracting strongly-typed semantic entities from scanner evidence.
#[derive(Debug, Clone)]
pub struct EntityExtractor {
    limits: SemanticExtractionLimits,
}

impl Default for EntityExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl EntityExtractor {
    /// Creates a new entity extractor with default safety limits.
    pub fn new() -> Self {
        Self {
            limits: SemanticExtractionLimits::default(),
        }
    }

    /// Creates a new entity extractor with custom safety limits.
    pub fn with_limits(limits: SemanticExtractionLimits) -> Self {
        Self { limits }
    }

    /// Extracts entities from a knowledge snapshot.
    pub fn extract_from_snapshot(&self, snapshot: &KnowledgeSnapshot) -> Vec<SemanticEntity> {
        self.extract_from_evidence(snapshot.evidence())
    }

    /// Extracts entities deterministically from a slice of evidence records.
    pub fn extract_from_evidence(&self, evidence_list: &[Evidence]) -> Vec<SemanticEntity> {
        let mut entity_map = BTreeMap::<EntityId, SemanticEntity>::new();

        for evidence in evidence_list {
            if entity_map.len() >= self.limits.max_entities {
                break;
            }

            if let Some(extracted) = self.project_evidence(evidence) {
                entity_map
                    .entry(extracted.id().clone())
                    .and_modify(|existing| {
                        let mut merged_attrs = existing.attributes().clone();
                        for (key, values) in extracted.attributes() {
                            if merged_attrs.len() < self.limits.max_attribute_keys {
                                let set = merged_attrs.entry(key.clone()).or_default();
                                for val in values {
                                    if set.len() < self.limits.max_values_per_attribute {
                                        set.insert(val.clone());
                                    }
                                }
                            }
                        }
                        let mut merged_sources = existing.source_evidence_ids().to_vec();
                        for src_id in extracted.source_evidence_ids() {
                            if merged_sources.len() < self.limits.max_source_evidence_ids {
                                merged_sources.push(src_id.clone());
                            }
                        }
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

        if val_str.len() > self.limits.max_value_bytes {
            return None;
        }

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
                    parse_canonical_endpoint(evidence.subject().as_str(), val_str, &self.limits)?;
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

                if let Some(canonical_ip) = parse_canonical_ip(raw_val) {
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
                } else if let Some(canonical_domain) = parse_canonical_domain(raw_val) {
                    let canonical_id =
                        EntityId::new(format!("{CANONICAL_ID_VERSION}:domain:{canonical_domain}"))
                            .ok()?;
                    let mut attrs = BTreeMap::new();
                    attrs.insert("domain".to_string(), BTreeSet::from([canonical_domain]));
                    Some(SemanticEntity::new(
                        canonical_id,
                        SemanticEntityType::Domain,
                        attrs,
                        vec![evidence.id().clone()],
                    ))
                } else {
                    None
                }
            },
            (EvidenceKind::Authentication, "token" | "jwt" | "bearer" | "cookie" | "api_key") => {
                // REDACTION GUARANTEE: Never store raw token in attributes
                let raw_token = val_str.trim();
                if raw_token.is_empty() {
                    return None;
                }

                let clean_token = strip_bearer_prefix(raw_token);
                if clean_token.is_empty() {
                    return None;
                }

                let kind = classify_auth_kind(predicate_name, clean_token);
                let fingerprint = hash_token(kind, clean_token);
                let canonical_id = EntityId::new(format!(
                    "{CANONICAL_ID_VERSION}:auth_artifact:{fingerprint}"
                ))
                .ok()?;

                let mut attrs = BTreeMap::new();
                attrs.insert(
                    "auth_kind".to_string(),
                    BTreeSet::from([kind.slug().to_string()]),
                );
                attrs.insert("fingerprint".to_string(), BTreeSet::from([fingerprint]));
                attrs.insert(
                    "length".to_string(),
                    BTreeSet::from([clean_token.len().to_string()]),
                );

                Some(SemanticEntity::new(
                    canonical_id,
                    SemanticEntityType::AuthArtifact,
                    attrs,
                    vec![evidence.id().clone()],
                ))
            },
            (EvidenceKind::Http, "header") => {
                let (header_name, _header_value) = parse_header_pair(val_str)?;
                let name_lower = header_name.to_lowercase();
                if name_lower.is_empty() {
                    return None;
                }

                // Model A (Global Name-Only Concept): Header identity represents the header concept name.
                // Values belong to evidence/relations and are NOT merged globally per header.
                let canonical_id =
                    EntityId::new(format!("{CANONICAL_ID_VERSION}:header:{name_lower}")).ok()?;
                let mut attrs = BTreeMap::new();
                attrs.insert("name".to_string(), BTreeSet::from([name_lower]));

                Some(SemanticEntity::new(
                    canonical_id,
                    SemanticEntityType::Header,
                    attrs,
                    vec![evidence.id().clone()],
                ))
            },
            // STRICT ALLOWLIST ONLY: Unsupported evidence or unknown predicates return None.
            // NEVER fallback to raw text or mistyped Endpoint entities!
            _ => None,
        }
    }
}

fn parse_canonical_ip(raw: &str) -> Option<String> {
    let clean = raw.trim();
    if clean.is_empty() {
        return None;
    }

    if let Some(v4) = parse_ipv4(clean) {
        return Some(v4);
    }

    if let Some(v6) = parse_ipv6(clean) {
        return Some(v6);
    }

    None
}

fn parse_ipv4(clean: &str) -> Option<String> {
    let parts: Vec<&str> = clean.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || (p.len() > 1 && p.starts_with('0')) {
            return None;
        }
        let val: u8 = p.parse().ok()?;
        octets[i] = val;
    }
    Some(format!(
        "{}.{}.{}.{}",
        octets[0], octets[1], octets[2], octets[3]
    ))
}

fn parse_ipv6(clean: &str) -> Option<String> {
    if !clean.contains(':') {
        return None;
    }

    let lower = clean.to_lowercase();
    let (left, right) = if let Some((l, r)) = lower.split_once("::") {
        if r.contains("::") {
            return None;
        }
        (l, Some(r))
    } else {
        (lower.as_str(), None)
    };

    let parse_hextets = |s: &str| -> Option<Vec<u16>> {
        if s.is_empty() {
            return Some(Vec::new());
        }
        let parts: Vec<&str> = s.split(':').collect();
        let mut res = Vec::with_capacity(parts.len());
        for p in parts {
            if p.is_empty() || p.len() > 4 {
                return None;
            }
            let val = u16::from_str_radix(p, 16).ok()?;
            res.push(val);
        }
        Some(res)
    };

    let left_hextets = parse_hextets(left)?;
    let right_hextets = match right {
        Some(r) => parse_hextets(r)?,
        None => Vec::new(),
    };

    let total = left_hextets.len() + right_hextets.len();
    if right.is_some() {
        if total >= 8 {
            return None;
        }
    } else if total != 8 {
        return None;
    }

    let mut full = [0u16; 8];
    for (i, &val) in left_hextets.iter().enumerate() {
        full[i] = val;
    }
    let zeros_count = 8 - total;
    for (i, &val) in right_hextets.iter().enumerate() {
        full[left_hextets.len() + zeros_count + i] = val;
    }

    let mut zero_runs = Vec::new();
    let mut in_zero = false;
    let mut start = 0;
    for (i, &val) in full.iter().enumerate() {
        if val == 0 {
            if !in_zero {
                in_zero = true;
                start = i;
            }
        } else if in_zero {
            in_zero = false;
            let len = i - start;
            if len > 1 {
                zero_runs.push((len, start));
            }
        }
    }
    if in_zero {
        let len = 8 - start;
        if len > 1 {
            zero_runs.push((len, start));
        }
    }

    let best_run = zero_runs.into_iter().max_by_key(|&(len, _)| len);

    let mut result = String::new();
    if let Some((len, start)) = best_run {
        let end = start + len;
        for (i, &val) in full[..start].iter().enumerate() {
            if i > 0 {
                result.push(':');
            }
            result.push_str(&format!("{val:x}"));
        }
        result.push_str("::");
        for (i, &val) in full[end..].iter().enumerate() {
            if i > 0 {
                result.push(':');
            }
            result.push_str(&format!("{val:x}"));
        }
    } else {
        for (i, &val) in full.iter().enumerate() {
            if i > 0 {
                result.push(':');
            }
            result.push_str(&format!("{val:x}"));
        }
    }

    Some(result)
}

fn parse_canonical_domain(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() || s.len() > 253 {
        return None;
    }

    if s.contains("://")
        || s.contains('/')
        || s.contains('@')
        || s.contains('#')
        || s.contains('?')
        || s.contains(':')
    {
        return None;
    }

    let trimmed = s.strip_suffix('.').unwrap_or(s);
    let lower = trimmed.to_lowercase();

    if lower.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }

    let labels: Vec<&str> = lower.split('.').collect();
    if labels.is_empty() {
        return None;
    }

    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return None;
        }
    }

    Some(lower)
}

fn strip_bearer_prefix(raw: &str) -> &str {
    let trimmed = raw.trim();
    if let Some(stripped) = trimmed.strip_prefix("Bearer ") {
        stripped.trim()
    } else if let Some(stripped) = trimmed.strip_prefix("bearer ") {
        stripped.trim()
    } else {
        trimmed
    }
}

fn hash_token(kind: AuthArtifactKind, clean_token: &str) -> String {
    let mut hasher = Sha256::new();
    let domain_sep = format!(
        "venom:auth-artifact:{CANONICAL_ID_VERSION}:{}:{clean_token}",
        kind.slug()
    );
    hasher.update(domain_sep.as_bytes());
    let result = hasher.finalize();
    result.iter().map(|b| format!("{b:02x}")).collect()
}

fn classify_auth_kind(predicate: &str, clean_token: &str) -> AuthArtifactKind {
    if predicate == "cookie" {
        return AuthArtifactKind::SessionCookie;
    }
    if predicate == "api_key" {
        return AuthArtifactKind::ApiKey;
    }

    if is_valid_jwt_structure(clean_token) {
        return AuthArtifactKind::Jwt;
    }

    if predicate == "bearer" || predicate == "token" {
        return AuthArtifactKind::BearerToken;
    }

    AuthArtifactKind::Unknown
}

fn is_valid_jwt_structure(raw: &str) -> bool {
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() != 3 {
        return false;
    }

    // Both header and payload segments must be valid base64url and parse into JSON objects
    is_valid_base64url_json_object(parts[0]) && is_valid_base64url_json_object(parts[1])
}

fn is_valid_base64url_json_object(segment: &str) -> bool {
    if segment.is_empty() {
        return false;
    }

    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .or_else(|_| {
            let pad = match segment.len() % 4 {
                2 => "==",
                3 => "=",
                _ => "",
            };
            base64::engine::general_purpose::URL_SAFE.decode(format!("{segment}{pad}"))
        });

    if let Ok(bytes) = decoded {
        if let Ok(serde_json::Value::Object(_)) = serde_json::from_slice(&bytes) {
            return true;
        }
    }

    false
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
    limits: &SemanticExtractionLimits,
) -> Option<(EntityId, String, Option<String>)> {
    let clean_val = val_str.trim();
    if clean_val.is_empty() {
        return None;
    }

    let val_lower = clean_val.to_lowercase();
    let target = if val_lower.starts_with("http://") || val_lower.starts_with("https://") {
        clean_val
    } else if clean_val.starts_with('/') {
        let subj_clean = subject_str.strip_prefix("endpoint:").unwrap_or(subject_str);
        if let Ok(base_url) = Url::parse(subj_clean) {
            let scheme = base_url.scheme();
            let host = base_url.host_str()?;
            let port_str = base_url.port().map_or(String::new(), |p| format!(":{p}"));
            let combined = format!("{scheme}://{host}{port_str}{clean_val}");
            let mut url = Url::parse(&combined).ok()?;
            url.set_query(None);
            url.set_fragment(None);
            let normalized_url = url.to_string();
            let canonical_str = format!("{CANONICAL_ID_VERSION}:endpoint:{normalized_url}#GET");
            let canonical_id = EntityId::new(canonical_str).ok()?;
            return Some((canonical_id, normalized_url, None));
        } else {
            return None;
        }
    } else {
        return None;
    };
    if target.len() > limits.max_url_bytes {
        return None;
    }

    let mut url = Url::parse(target).ok()?;
    let scheme = url.scheme().to_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }

    // USERINFO REDACTION: Remove username/password completely from canonical identity and attributes
    if !url.username().is_empty() || url.password().is_some() {
        let _ = url.set_username("");
        let _ = url.set_password(None);
    }

    // Strip query and fragment from canonical endpoint identity
    url.set_query(None);
    url.set_fragment(None);

    let host = url.host_str()?.to_lowercase();

    // Default port normalization
    let port_suffix = match (scheme.as_str(), url.port()) {
        ("http", Some(80)) | ("http", None) => String::new(),
        ("https", Some(443)) | ("https", None) => String::new(),
        (_, Some(p)) => format!(":{p}"),
        (_, None) => String::new(),
    };

    let path = url.path();
    let normalized_url = format!("{scheme}://{host}{port_suffix}{path}");

    // Method comes from typed evidence or defaults strictly to GET (never from URL fragment!)
    let method_suffix = "GET";
    let canonical_str = format!("{CANONICAL_ID_VERSION}:endpoint:{normalized_url}#{method_suffix}");
    let canonical_id = EntityId::new(canonical_str).ok()?;

    Some((canonical_id, normalized_url, None))
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
    fn unsupported_evidence_produces_no_entity() {
        let ev = Evidence::new(
            subject(),
            EvidenceKind::Custom("unsupported_kind".to_string()),
            KnowledgePredicate::new("custom", "unsupported_pred").unwrap(),
            EvidenceValue::Text("raw-unsupported-value".into()),
            EvidenceSource::new("scanner", "test").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let extractor = EntityExtractor::new();
        let entities = extractor.extract_from_evidence(&[ev]);
        assert!(entities.is_empty());
    }

    #[test]
    fn unknown_authentication_predicate_never_leaks_raw_value() {
        let secret = "super-secret-client-credential-12345";
        let ev = Evidence::new(
            subject(),
            EvidenceKind::Authentication,
            KnowledgePredicate::new("authentication", "client_secret").unwrap(),
            EvidenceValue::Text(secret.into()),
            EvidenceSource::new("scanner", "test").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let extractor = EntityExtractor::new();
        let entities = extractor.extract_from_evidence(&[ev]);
        assert!(
            entities.is_empty(),
            "Unknown authentication predicate produced an unapproved entity!"
        );
    }

    #[test]
    fn unknown_http_predicate_never_becomes_endpoint() {
        let ev = Evidence::new(
            subject(),
            EvidenceKind::Http,
            KnowledgePredicate::new("http", "unknown_http_meta").unwrap(),
            EvidenceValue::Text("random_http_value".into()),
            EvidenceSource::new("scanner", "test").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let extractor = EntityExtractor::new();
        let entities = extractor.extract_from_evidence(&[ev]);
        assert!(entities.is_empty());
    }

    #[test]
    fn raw_secret_never_appears_in_any_serialized_entity() {
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
        let serialized = serde_json::to_string(&entities).unwrap();

        assert!(
            !serialized.contains(secret_jwt),
            "Raw secret token leaked into serialized entity JSON output!"
        );
    }

    #[test]
    fn equivalent_ipv6_forms_produce_same_id() {
        let ev1 = Evidence::new(
            subject(),
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "ip").unwrap(),
            EvidenceValue::Text("2001:0db8:0000:0000:0000:0000:0000:0001".into()),
            EvidenceSource::new("scanner", "dns").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let ev2 = Evidence::new(
            subject(),
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "ip").unwrap(),
            EvidenceValue::Text("2001:db8::1".into()),
            EvidenceSource::new("scanner", "dns").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let extractor = EntityExtractor::new();
        let e1 = &extractor.extract_from_evidence(&[ev1])[0];
        let e2 = &extractor.extract_from_evidence(&[ev2])[0];

        assert_eq!(e1.id(), e2.id());
        assert_eq!(e1.id().as_str(), "v1:ip:2001:db8::1");
    }

    #[test]
    fn invalid_ip_does_not_become_domain() {
        let ev = Evidence::new(
            subject(),
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "ip").unwrap(),
            EvidenceValue::Text("not a domain or ip".into()),
            EvidenceSource::new("scanner", "dns").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let extractor = EntityExtractor::new();
        let entities = extractor.extract_from_evidence(&[ev]);
        assert!(entities.is_empty());
    }

    #[test]
    fn trailing_dot_domain_matches_non_trailing_form() {
        let ev1 = Evidence::new(
            subject(),
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "domain").unwrap(),
            EvidenceValue::Text("example.test.".into()),
            EvidenceSource::new("scanner", "dns").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let ev2 = Evidence::new(
            subject(),
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "domain").unwrap(),
            EvidenceValue::Text("example.test".into()),
            EvidenceSource::new("scanner", "dns").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let extractor = EntityExtractor::new();
        let e1 = &extractor.extract_from_evidence(&[ev1])[0];
        let e2 = &extractor.extract_from_evidence(&[ev2])[0];

        assert_eq!(e1.id(), e2.id());
        assert_eq!(e1.id().as_str(), "v1:domain:example.test");
    }

    #[test]
    fn malformed_hostname_produces_no_entity() {
        let ev = Evidence::new(
            subject(),
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "domain").unwrap(),
            EvidenceValue::Text("https://example.com/path".into()),
            EvidenceSource::new("scanner", "dns").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let extractor = EntityExtractor::new();
        let entities = extractor.extract_from_evidence(&[ev]);
        assert!(entities.is_empty());
    }

    #[test]
    fn url_userinfo_never_appears_in_id_or_attributes() {
        let secret_url = "https://admin:secret_pass123@example.test/api/v1/user";
        let ev = Evidence::new(
            EntityId::new("endpoint:https://example.test/api/v1/user").unwrap(),
            EvidenceKind::Http,
            KnowledgePredicate::new("http", "endpoint").unwrap(),
            EvidenceValue::Text(secret_url.into()),
            EvidenceSource::new("scanner", "test").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let extractor = EntityExtractor::new();
        let entities = extractor.extract_from_evidence(&[ev]);
        assert_eq!(entities.len(), 1);
        let entity = &entities[0];

        let serialized = serde_json::to_string(entity).unwrap();
        assert!(!serialized.contains("secret_pass123"));
        assert!(!serialized.contains("admin"));
        assert_eq!(
            entity.id().as_str(),
            "v1:endpoint:https://example.test/api/v1/user#GET"
        );
    }

    #[test]
    fn url_fragment_is_not_interpreted_as_http_method() {
        let ev = Evidence::new(
            subject(),
            EvidenceKind::Http,
            KnowledgePredicate::new("http", "endpoint").unwrap(),
            EvidenceValue::Text("https://example.test/docs#section".into()),
            EvidenceSource::new("scanner", "test").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let extractor = EntityExtractor::new();
        let entities = extractor.extract_from_evidence(&[ev]);
        assert_eq!(entities.len(), 1);
        assert_eq!(
            entities[0].id().as_str(),
            "v1:endpoint:https://example.test/docs#GET"
        );
    }

    #[test]
    fn ipv6_endpoint_is_canonicalized() {
        let ev = Evidence::new(
            subject(),
            EvidenceKind::Http,
            KnowledgePredicate::new("http", "endpoint").unwrap(),
            EvidenceValue::Text("https://[2001:0db8:0000:0000:0000:0000:0000:0001]:443/api".into()),
            EvidenceSource::new("scanner", "test").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let extractor = EntityExtractor::new();
        let entities = extractor.extract_from_evidence(&[ev]);
        assert_eq!(entities.len(), 1);
        assert_eq!(
            entities[0].id().as_str(),
            "v1:endpoint:https://[2001:db8::1]/api#GET"
        );
    }

    #[test]
    fn malformed_url_produces_no_entity() {
        let ev = Evidence::new(
            subject(),
            EvidenceKind::Http,
            KnowledgePredicate::new("http", "endpoint").unwrap(),
            EvidenceValue::Text("not_a_valid_url".into()),
            EvidenceSource::new("scanner", "test").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let extractor = EntityExtractor::new();
        let entities = extractor.extract_from_evidence(&[ev]);
        assert!(entities.is_empty());
    }

    #[test]
    fn explicit_get_and_default_get_produce_identical_entity() {
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
            EvidenceValue::Text("https://example.test/api/user#GET".into()),
            EvidenceSource::new("scanner", "test").unwrap(),
            ConfidenceScore::from_percent(90).unwrap(),
        );

        let extractor = EntityExtractor::new();
        let e1 = &extractor.extract_from_evidence(&[ev1])[0];
        let e2 = &extractor.extract_from_evidence(&[ev2])[0];

        assert_eq!(e1.id(), e2.id());
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
        let entities1 = extractor.extract_from_evidence(&[ev1.clone(), ev2.clone()]);
        let entities2 = extractor.extract_from_evidence(&[ev2, ev1]);

        let bytes1 = serde_json::to_vec(&entities1).unwrap();
        let bytes2 = serde_json::to_vec(&entities2).unwrap();

        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn fingerprint_is_domain_separated_by_artifact_kind() {
        let raw_token = "secret123";
        let fp_bearer = hash_token(AuthArtifactKind::BearerToken, raw_token);
        let fp_cookie = hash_token(AuthArtifactKind::SessionCookie, raw_token);

        assert_ne!(fp_bearer, fp_cookie);
        assert!(fp_bearer.len() == 64);
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

        let extractor = EntityExtractor::new();
        let entities = extractor.extract_from_evidence(&[ev1]);

        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].id().as_str(), "v1:header:authorization");
        assert_eq!(
            entities[0]
                .attributes()
                .get("name")
                .unwrap()
                .iter()
                .next()
                .unwrap(),
            "authorization"
        );
        assert!(
            !entities[0].attributes().contains_key("value"),
            "Header entity (Model A name-only concept) must not store header values globally!"
        );
    }
}
