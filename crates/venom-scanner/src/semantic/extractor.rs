//! Deterministic entity extraction rules mapping evidence to semantic entities.

use base64::Engine;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::str::FromStr;
use url::Url;
use venom_core::{EntityId, Evidence, EvidenceId, EvidenceKind, EvidenceValue};

use crate::knowledge::KnowledgeSnapshot;
use crate::semantic::entity::{
    AuthArtifactKind, SemanticEntity, SemanticEntityType, SemanticExtractionLimits,
    SemanticExtractionResult,
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

    /// Returns a reference to the extractor limits.
    pub fn limits(&self) -> &SemanticExtractionLimits {
        &self.limits
    }

    /// Extracts entities from a knowledge snapshot.
    pub fn extract_from_snapshot(&self, snapshot: &KnowledgeSnapshot) -> SemanticExtractionResult {
        self.extract_from_evidence(snapshot.evidence())
    }

    /// Extracts entities deterministically from a slice of evidence records.
    pub fn extract_from_evidence(&self, evidence_list: &[Evidence]) -> SemanticExtractionResult {
        let mut sorted_evidence: Vec<&Evidence> = evidence_list.iter().collect();
        sorted_evidence.sort_by_key(|e| e.id());

        let mut entity_map = BTreeMap::<
            EntityId,
            (
                SemanticEntityType,
                BTreeMap<String, BTreeSet<String>>,
                BTreeSet<EvidenceId>,
            ),
        >::new();

        for evidence in sorted_evidence {
            if let Some(extracted) = self.project_evidence(evidence) {
                let (id, etype, attrs, sources) = extracted.into_parts();
                let entry = entity_map
                    .entry(id)
                    .or_insert_with(|| (etype, BTreeMap::new(), BTreeSet::new()));

                for (k, vals) in attrs {
                    entry.1.entry(k).or_default().extend(vals);
                }
                entry.2.extend(sources);
            }
        }

        let mut dropped_entities = 0;
        let mut dropped_attributes = 0;
        let mut dropped_sources = 0;
        let mut truncated = false;

        // Truncate entity count canonically (BTreeMap keys are canonically sorted EntityIds)
        if entity_map.len() > self.limits.max_entities {
            dropped_entities = entity_map.len() - self.limits.max_entities;
            truncated = true;
            let keys_to_keep: Vec<EntityId> = entity_map
                .keys()
                .take(self.limits.max_entities)
                .cloned()
                .collect();
            entity_map.retain(|k, _| keys_to_keep.contains(k));
        }

        let mut final_entities = Vec::with_capacity(entity_map.len());

        for (id, (etype, mut attrs, sources)) in entity_map {
            let source_vec: Vec<EvidenceId> = if sources.len() > self.limits.max_source_evidence_ids
            {
                dropped_sources += sources.len() - self.limits.max_source_evidence_ids;
                truncated = true;
                sources
                    .into_iter()
                    .take(self.limits.max_source_evidence_ids)
                    .collect()
            } else {
                sources.into_iter().collect()
            };

            if attrs.len() > self.limits.max_attribute_keys {
                dropped_attributes += attrs.len() - self.limits.max_attribute_keys;
                truncated = true;
                let attr_keys_to_keep: Vec<String> = attrs
                    .keys()
                    .take(self.limits.max_attribute_keys)
                    .cloned()
                    .collect();
                attrs.retain(|k, _| attr_keys_to_keep.contains(k));
            }

            for values in attrs.values_mut() {
                if values.len() > self.limits.max_values_per_attribute {
                    dropped_attributes += values.len() - self.limits.max_values_per_attribute;
                    truncated = true;
                    let val_set_to_keep: BTreeSet<String> = values
                        .iter()
                        .take(self.limits.max_values_per_attribute)
                        .cloned()
                        .collect();
                    *values = val_set_to_keep;
                }
            }

            final_entities.push(SemanticEntity::new(id, etype, attrs, source_vec));
        }

        SemanticExtractionResult {
            entities: final_entities,
            truncated,
            dropped_entities,
            dropped_attributes,
            dropped_sources,
        }
    }

    fn project_evidence(&self, evidence: &Evidence) -> Option<SemanticEntity> {
        let predicate = evidence.predicate();
        let predicate_namespace = predicate.namespace();
        let predicate_name = predicate.name();

        let val_str = match evidence.value() {
            EvidenceValue::Text(s) => s.as_str(),
            _ => return None,
        };

        if val_str.len() > self.limits.max_value_bytes {
            return None;
        }

        match (evidence.kind(), predicate_namespace, predicate_name) {
            (
                EvidenceKind::Technology,
                "technology",
                "web-server" | "language" | "framework" | "ui-framework",
            ) => {
                let name = val_str.trim();
                if name.is_empty() {
                    return None;
                }
                if !name.chars().any(|ch| ch.is_ascii_alphabetic()) {
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
            (EvidenceKind::Http, "http.request", "url") => {
                let (canonical_id, url_str) = parse_canonical_endpoint(
                    evidence.subject().as_str(),
                    val_str,
                    &self.limits,
                )?;
                let mut attrs = BTreeMap::new();
                attrs.insert("url".to_string(), BTreeSet::from([url_str]));

                Some(SemanticEntity::new(
                    canonical_id,
                    SemanticEntityType::Endpoint,
                    attrs,
                    vec![evidence.id().clone()],
                ))
            },
            (EvidenceKind::Http, "http.request", "method") => {
                let (canonical_id, url_str) = parse_canonical_endpoint(
                    evidence.subject().as_str(),
                    "",
                    &self.limits,
                )?;
                let normalized_method = normalize_http_method(val_str)?;

                let mut attrs = BTreeMap::new();
                attrs.insert("url".to_string(), BTreeSet::from([url_str]));
                attrs.insert("method".to_string(), BTreeSet::from([normalized_method]));

                Some(SemanticEntity::new(
                    canonical_id,
                    SemanticEntityType::Endpoint,
                    attrs,
                    vec![evidence.id().clone()],
                ))
            },
            (EvidenceKind::Dns, "dns", "ip") => {
                let raw_val = val_str.trim();
                if raw_val.is_empty() {
                    return None;
                }
                let canonical_ip = parse_canonical_ip(raw_val)?;
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
            },
            (EvidenceKind::Dns, "dns", "domain" | "hostname") => {
                let raw_val = val_str.trim();
                if raw_val.is_empty() {
                    return None;
                }
                let canonical_domain = parse_canonical_domain(raw_val)?;
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
            },
            (
                EvidenceKind::Authentication,
                "authentication",
                "api_key" | "bearer" | "jwt",
            ) => {
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
            (EvidenceKind::Http, "http.header", header_name) => {
                let name_lower = header_name.to_lowercase();
                if !is_valid_header_name(&name_lower) {
                    return None;
                }
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
    let ip = IpAddr::from_str(clean).ok()?;
    Some(ip.to_string())
}

fn parse_canonical_domain(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() || s.len() > 253 {
        return None;
    }

    if parse_canonical_ip(s).is_some() {
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

    if let Some(tld) = labels.last() {
        if tld.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
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

fn is_valid_header_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    name.bytes().all(|b| {
        matches!(
            b,
            b'a'..=b'z'
                | b'A'..=b'Z'
                | b'0'..=b'9'
                | b'!'
                | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
    })
}

fn parse_canonical_endpoint(
    subject_str: &str,
    val_str: &str,
    limits: &SemanticExtractionLimits,
) -> Option<(EntityId, String)> {
    let clean_val = val_str.trim();
    let source_url = if clean_val.is_empty() {
        subject_str
    } else {
        clean_val
    };

    let unstripped_target = source_url.strip_prefix("endpoint:").unwrap_or(source_url);

    let target_url_str = if unstripped_target.starts_with('/') {
        let subj_clean = subject_str.strip_prefix("endpoint:").unwrap_or(subject_str);
        let base_url = Url::parse(subj_clean).ok()?;
        base_url.join(unstripped_target).ok()?.to_string()
    } else {
        unstripped_target.to_string()
    };

    if target_url_str.len() > limits.max_url_bytes {
        return None;
    }

    let mut url = Url::parse(&target_url_str).ok()?;
    let scheme = url.scheme().to_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }

    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);

    if (scheme == "http" && url.port() == Some(80))
        || (scheme == "https" && url.port() == Some(443))
    {
        let _ = url.set_port(None);
    }

    let normalized_url = url.to_string();

    let canonical_str = format!("{CANONICAL_ID_VERSION}:endpoint:{normalized_url}");
    let canonical_id = EntityId::new(canonical_str).ok()?;
    Some((canonical_id, normalized_url))
}

fn normalize_http_method(raw_method: &str) -> Option<String> {
    let trimmed = raw_method.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() > 20 {
        return None;
    }

    if !trimmed
        .as_bytes()
        .iter()
        .all(|b| is_token_char(*b as char))
    {
        return None;
    }
    Some(trimmed.to_ascii_uppercase())
}

fn is_token_char(byte: char) -> bool {
    matches!(
        byte,
        '0'..='9'
            | 'A'..='Z'
            | 'a'..='z'
            | '!'
            | '#'
            | '$'
            | '%'
            | '&'
            | '\''
            | '*'
            | '+'
            | '-'
            | '.'
            | '^'
            | '_'
            | '`'
            | '|'
            | '~'
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use venom_core::{ConfidenceScore, EvidenceSource, KnowledgePredicate};

    fn subject() -> EntityId {
        EntityId::new("endpoint:https://example.test/api/user").unwrap()
    }

    fn source() -> EvidenceSource {
        EvidenceSource::new("scanner", "test").unwrap()
    }

    fn ev(kind: EvidenceKind, predicate: KnowledgePredicate, value: EvidenceValue) -> Evidence {
        Evidence::new(
            subject(),
            kind,
            predicate,
            value,
            source(),
            ConfidenceScore::from_percent(50).unwrap(),
        )
    }

    fn ev_subj(
        subj: EntityId,
        kind: EvidenceKind,
        predicate: KnowledgePredicate,
        value: EvidenceValue,
    ) -> Evidence {
        Evidence::new(
            subj,
            kind,
            predicate,
            value,
            source(),
            ConfidenceScore::from_percent(50).unwrap(),
        )
    }

    #[test]
    fn unsupported_evidence_produces_no_entity() {
        let extractor = EntityExtractor::new();
        let e = ev(
            EvidenceKind::Custom("unsupported_kind".to_string()),
            KnowledgePredicate::new("custom", "unsupported_pred").unwrap(),
            EvidenceValue::Text("raw-unsupported-value".into()),
        );
        let res = extractor.extract_from_evidence(&[e]);
        assert!(res.entities.is_empty());
    }

    #[test]
    fn namespace_collision_is_ignored() {
        let extractor = EntityExtractor::new();
        let e = ev(
            EvidenceKind::Http,
            KnowledgePredicate::new("http.request", "method").unwrap(),
            EvidenceValue::Text("GET".into()),
        );
        let e2 = ev(
            EvidenceKind::Http,
            KnowledgePredicate::new("api.request", "url").unwrap(),
            EvidenceValue::Text("https://example.test/admin".to_string()),
        );
        let e3 = ev(
            EvidenceKind::Http,
            KnowledgePredicate::new("api.request", "method").unwrap(),
            EvidenceValue::Text("GET".into()),
        );

        let res1 = extractor.extract_from_evidence(&[e]);
        let res2 = extractor.extract_from_evidence(&[e2]);
        let res3 = extractor.extract_from_evidence(&[e3]);
        assert_eq!(res1.entities.len(), 1);
        assert_eq!(res1.entities[0].id().as_str(), "v1:endpoint:https://example.test/api/user");
        assert!(res2.entities.is_empty());
        assert!(res3.entities.is_empty());
    }

    #[test]
    fn custom_predicate_namespace_does_not_route_as_http_method() {
        let extractor = EntityExtractor::new();
        let e = ev(
            EvidenceKind::Http,
            KnowledgePredicate::new("custom", "method").unwrap(),
            EvidenceValue::Text("GET".into()),
        );
        let res = extractor.extract_from_evidence(&[e]);
        assert!(res.entities.is_empty());
    }

    #[test]
    fn unknown_authentication_predicate_never_leaks_raw_value() {
        let extractor = EntityExtractor::new();
        let e = ev(
            EvidenceKind::Authentication,
            KnowledgePredicate::new("authentication", "client_secret").unwrap(),
            EvidenceValue::Text("super_secret_token_value_12345".into()),
        );
        let res = extractor.extract_from_evidence(&[e]);
        assert!(res.entities.is_empty());
    }

    #[test]
    fn raw_secret_never_appears_in_any_serialized_entity() {
        let extractor = EntityExtractor::new();
        let secret = "super_secret_jwt_payload_value";
        let e = ev(
            EvidenceKind::Authentication,
            KnowledgePredicate::new("authentication", "bearer").unwrap(),
            EvidenceValue::Text(secret.into()),
        );
        let res = extractor.extract_from_evidence(&[e]);
        assert_eq!(res.entities.len(), 1);
        let json = serde_json::to_string(&res.entities[0]).unwrap();
        assert!(!json.contains(secret));
    }

    #[test]
    fn equivalent_ipv6_forms_produce_same_id() {
        let extractor = EntityExtractor::new();
        let ev1 = ev(
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "ip").unwrap(),
            EvidenceValue::Text("2001:0db8:0000:0000:0000:0000:0000:0001".into()),
        );
        let ev2 = ev(
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "ip").unwrap(),
            EvidenceValue::Text("2001:db8::1".into()),
        );
        let res1 = extractor.extract_from_evidence(&[ev1]);
        let res2 = extractor.extract_from_evidence(&[ev2]);
        assert_eq!(res1.entities[0].id(), res2.entities[0].id());
        assert_eq!(res1.entities[0].id().as_str(), "v1:ip:2001:db8::1");
    }

    #[test]
    fn invalid_ip_does_not_become_domain() {
        let extractor = EntityExtractor::new();
        let e = ev(
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "ip").unwrap(),
            EvidenceValue::Text("999.999.999.999".into()),
        );
        let res = extractor.extract_from_evidence(&[e]);
        assert!(res.entities.is_empty());
    }

    #[test]
    fn trailing_dot_domain_matches_non_trailing_form() {
        let extractor = EntityExtractor::new();
        let ev1 = ev(
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "domain").unwrap(),
            EvidenceValue::Text("EXAMPLE.TEST.".into()),
        );
        let ev2 = ev(
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "domain").unwrap(),
            EvidenceValue::Text("example.test".into()),
        );
        let res1 = extractor.extract_from_evidence(&[ev1]);
        let res2 = extractor.extract_from_evidence(&[ev2]);
        assert_eq!(res1.entities[0].id(), res2.entities[0].id());
    }

    #[test]
    fn malformed_hostname_produces_no_entity() {
        let extractor = EntityExtractor::new();
        let e = ev(
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "hostname").unwrap(),
            EvidenceValue::Text("invalid_host_name#label".into()),
        );
        let res = extractor.extract_from_evidence(&[e]);
        assert!(res.entities.is_empty());
    }

    #[test]
    fn url_userinfo_never_appears_in_id_or_attributes() {
        let extractor = EntityExtractor::new();
        let e = ev(
            EvidenceKind::Http,
            KnowledgePredicate::new("http.request", "url").unwrap(),
            EvidenceValue::Text("https://admin:secret123@example.test/api/v1/users".into()),
        );
        let res = extractor.extract_from_evidence(&[e]);
        assert_eq!(res.entities.len(), 1);
        let json = serde_json::to_string(&res.entities[0]).unwrap();
        assert!(!json.contains("admin"));
        assert!(!json.contains("secret123"));
        assert_eq!(
            res.entities[0].id().as_str(),
            "v1:endpoint:https://example.test/api/v1/users"
        );
    }

    #[test]
    fn url_fragment_is_not_interpreted_as_http_method() {
        let extractor = EntityExtractor::new();
        let e = ev(
            EvidenceKind::Http,
            KnowledgePredicate::new("http.request", "url").unwrap(),
            EvidenceValue::Text("https://example.test/api/v1/users#DELETE".into()),
        );
        let res = extractor.extract_from_evidence(&[e]);
        assert_eq!(res.entities.len(), 1);
        assert_eq!(
            res.entities[0].id().as_str(),
            "v1:endpoint:https://example.test/api/v1/users"
        );
        assert!(res.entities[0].attributes().get("method").is_none());
    }

    #[test]
    fn ipv6_endpoint_is_canonicalized() {
        let extractor = EntityExtractor::new();
        let e = ev(
            EvidenceKind::Http,
            KnowledgePredicate::new("http.request", "url").unwrap(),
            EvidenceValue::Text(
                "http://[2001:0db8:0000:0000:0000:0000:0000:0001]:80/api/v1".into(),
            ),
        );
        let res = extractor.extract_from_evidence(&[e]);
        assert_eq!(res.entities.len(), 1);
        assert_eq!(
            res.entities[0].id().as_str(),
            "v1:endpoint:http://[2001:db8::1]/api/v1"
        );
    }

    #[test]
    fn malformed_url_produces_no_entity() {
        let extractor = EntityExtractor::new();
        let e = ev(
            EvidenceKind::Http,
            KnowledgePredicate::new("http.request", "url").unwrap(),
            EvidenceValue::Text("not_a_valid_url".into()),
        );
        let res = extractor.extract_from_evidence(&[e]);
        assert!(res.entities.is_empty());
    }

    #[test]
    fn get_and_post_are_distinct_when_method_is_observed() {
        let extractor = EntityExtractor::new();
        let res_get = extractor.extract_from_evidence(&[ev_subj(
            subject(),
            EvidenceKind::Http,
            KnowledgePredicate::new("http.request", "method").unwrap(),
            EvidenceValue::Text("GET".into()),
        )]);
        let res_post = extractor.extract_from_evidence(&[ev_subj(
            subject(),
            EvidenceKind::Http,
            KnowledgePredicate::new("http.request", "method").unwrap(),
            EvidenceValue::Text("POST".into()),
        )]);
        assert_eq!(
            res_get.entities[0].id().as_str(),
            "v1:endpoint:https://example.test/api/user"
        );
        assert_eq!(
            res_post.entities[0].id().as_str(),
            "v1:endpoint:https://example.test/api/user"
        );
        assert_ne!(
            res_get.entities[0].attributes().get("method"),
            res_post.entities[0].attributes().get("method")
        );
    }

    #[test]
    fn method_with_whitespace_is_rejected() {
        let extractor = EntityExtractor::new();
        let res = extractor.extract_from_evidence(&[ev_subj(
            subject(),
            EvidenceKind::Http,
            KnowledgePredicate::new("http.request", "method").unwrap(),
            EvidenceValue::Text(" G\nET ".into()),
        )]);
        assert_eq!(res.entities.len(), 0);
    }

    #[test]
    fn method_with_separator_is_rejected() {
        let extractor = EntityExtractor::new();
        let res = extractor.extract_from_evidence(&[ev_subj(
            subject(),
            EvidenceKind::Http,
            KnowledgePredicate::new("http.request", "method").unwrap(),
            EvidenceValue::Text("GET/POST".into()),
        )]);
        assert_eq!(res.entities.len(), 0);
    }

    #[test]
    fn method_with_unreasonably_long_token_is_rejected() {
        let extractor = EntityExtractor::new();
        let res = extractor.extract_from_evidence(&[ev_subj(
            subject(),
            EvidenceKind::Http,
            KnowledgePredicate::new("http.request", "method").unwrap(),
            EvidenceValue::Text("VERYLONGCUSTOMHTTPMETHODNAME".into()),
        )]);
        assert_eq!(res.entities.len(), 0);
    }

    #[test]
    fn missing_method_does_not_claim_observed_get() {
        let extractor = EntityExtractor::new();
        let e = ev(
            EvidenceKind::Http,
            KnowledgePredicate::new("http.request", "url").unwrap(),
            EvidenceValue::Text("https://example.test/api/user".into()),
        );
        let res = extractor.extract_from_evidence(&[e]);
        assert_eq!(
            res.entities[0].id().as_str(),
            "v1:endpoint:https://example.test/api/user"
        );
        assert!(res.entities[0].attributes().get("method").is_none());
    }

    #[test]
    fn same_input_serializes_byte_for_byte_identically() {
        let extractor = EntityExtractor::new();
        let ev1 = ev(
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "domain").unwrap(),
            EvidenceValue::Text("example.test".into()),
        );
        let ev2 = ev(
            EvidenceKind::Technology,
            KnowledgePredicate::new("tech", "framework").unwrap(),
            EvidenceValue::Text("actix-web".into()),
        );
        let res1 = extractor.extract_from_evidence(&[ev1.clone(), ev2.clone()]);
        let res2 = extractor.extract_from_evidence(&[ev2, ev1]);

        let bytes1 = serde_json::to_vec(&res1.entities).unwrap();
        let bytes2 = serde_json::to_vec(&res2.entities).unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn fingerprint_is_domain_separated_by_artifact_kind() {
        let extractor = EntityExtractor::new();
        let token = "same_secret_value_12345";
        let ev1 = ev(
            EvidenceKind::Authentication,
            KnowledgePredicate::new("authentication", "bearer").unwrap(),
            EvidenceValue::Text(token.into()),
        );
        let ev2 = ev(
            EvidenceKind::Authentication,
            KnowledgePredicate::new("authentication", "api_key").unwrap(),
            EvidenceValue::Text(token.into()),
        );
        let res1 = extractor.extract_from_evidence(&[ev1]);
        let res2 = extractor.extract_from_evidence(&[ev2]);

        let fp1 = res1.entities[0]
            .attributes()
            .get("fingerprint")
            .unwrap()
            .iter()
            .next()
            .unwrap();
        let fp2 = res2.entities[0]
            .attributes()
            .get("fingerprint")
            .unwrap()
            .iter()
            .next()
            .unwrap();
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn header_values_are_not_persisted() {
        let extractor = EntityExtractor::new();
        let e = ev(
            EvidenceKind::Http,
            KnowledgePredicate::new("http.header", "authorization").unwrap(),
            EvidenceValue::Text("Authorization: Bearer my_secret_token".into()),
        );
        let res = extractor.extract_from_evidence(&[e]);
        assert_eq!(res.entities.len(), 1);
        let json = serde_json::to_string(&res.entities[0]).unwrap();
        assert!(!json.contains("my_secret_token"));
        assert!(!json.contains("Authorization"));
        assert_eq!(res.entities[0].id().as_str(), "v1:header:authorization");
        assert_eq!(res.entities[0].attributes().len(), 1);
        assert!(
            res.entities[0].attributes().contains_key("name")
        );
    }

    #[test]
    fn bounded_output_is_independent_of_input_order() {
        let limits = SemanticExtractionLimits::new(1, 50, 50, 4096, 100, 2048).unwrap();
        let extractor = EntityExtractor::with_limits(limits);

        let ev1 = ev(
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "domain").unwrap(),
            EvidenceValue::Text("aaa.example.test".into()),
        );
        let ev2 = ev(
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "domain").unwrap(),
            EvidenceValue::Text("zzz.example.test".into()),
        );

        let res1 = extractor.extract_from_evidence(&[ev1.clone(), ev2.clone()]);
        let res2 = extractor.extract_from_evidence(&[ev2, ev1]);

        assert_eq!(res1.entities, res2.entities);
        assert_eq!(res1.dropped_entities, 1);
        assert_eq!(res2.dropped_entities, 1);
        assert!(res1.truncated);
        assert!(res2.truncated);
    }

    #[test]
    fn reaching_entity_limit_still_merges_retained_entities() {
        let limits = SemanticExtractionLimits::new(1, 50, 50, 4096, 100, 2048).unwrap();
        let extractor = EntityExtractor::with_limits(limits);

        let ev1 = ev(
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "domain").unwrap(),
            EvidenceValue::Text("aaa.example.test".into()),
        );
        let ev2 = ev(
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "domain").unwrap(),
            EvidenceValue::Text("zzz.example.test".into()),
        );
        let ev3 = ev(
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "domain").unwrap(),
            EvidenceValue::Text("aaa.example.test".into()),
        );

        let res = extractor.extract_from_evidence(&[ev1, ev2, ev3]);
        assert_eq!(res.entities.len(), 1);
        assert_eq!(res.entities[0].id().as_str(), "v1:domain:aaa.example.test");
        assert_eq!(res.entities[0].source_evidence_ids().len(), 2);
    }

    #[test]
    fn duplicate_source_ids_do_not_consume_source_budget() {
        let limits = SemanticExtractionLimits::new(10, 50, 50, 4096, 2, 2048).unwrap();
        let extractor = EntityExtractor::with_limits(limits);

        let ev1 = ev(
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "domain").unwrap(),
            EvidenceValue::Text("example.test".into()),
        );

        let res = extractor.extract_from_evidence(&[ev1.clone(), ev1.clone(), ev1]);
        assert_eq!(res.entities[0].source_evidence_ids().len(), 1);
        assert_eq!(res.dropped_sources, 0);
        assert!(!res.truncated);
    }

    #[test]
    fn invalid_ip_predicate_never_falls_back_to_domain() {
        let extractor = EntityExtractor::new();
        let e = ev(
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "ip").unwrap(),
            EvidenceValue::Text("example.test".into()),
        );
        let res = extractor.extract_from_evidence(&[e]);
        assert!(res.entities.is_empty());
    }

    #[test]
    fn domain_predicate_never_silently_changes_type_to_ip() {
        let extractor = EntityExtractor::new();
        let e = ev(
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "domain").unwrap(),
            EvidenceValue::Text("192.0.2.1".into()),
        );
        let res = extractor.extract_from_evidence(&[e]);
        assert!(res.entities.is_empty());
    }

    #[test]
    fn numeric_invalid_ipv4_is_rejected() {
        let extractor = EntityExtractor::new();
        let e = ev(
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "ip").unwrap(),
            EvidenceValue::Text("999.999.999.999".into()),
        );
        let res = extractor.extract_from_evidence(&[e]);
        assert!(res.entities.is_empty());
    }

    #[test]
    fn equal_zero_runs_use_leftmost_compression() {
        let extractor = EntityExtractor::new();
        let e = ev(
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "ip").unwrap(),
            EvidenceValue::Text("2001:db8:0:0:1:0:0:1".into()),
        );
        let res = extractor.extract_from_evidence(&[e]);
        assert_eq!(res.entities[0].id().as_str(), "v1:ip:2001:db8::1:0:0:1");
    }

    #[test]
    fn all_accepted_ipv6_forms_round_trip_canonically() {
        let extractor = EntityExtractor::new();
        let e = ev(
            EvidenceKind::Dns,
            KnowledgePredicate::new("dns", "ip").unwrap(),
            EvidenceValue::Text("FE80:0000:0000:0000:0202:B3FF:FE1E:8329".into()),
        );
        let res = extractor.extract_from_evidence(&[e]);
        assert_eq!(
            res.entities[0].id().as_str(),
            "v1:ip:fe80::202:b3ff:fe1e:8329"
        );
    }

    #[test]
    fn relative_url_respects_max_url_bytes() {
        let limits = SemanticExtractionLimits::new(10, 50, 50, 4096, 100, 20).unwrap();
        let extractor = EntityExtractor::with_limits(limits);
        let e = ev(
            EvidenceKind::Http,
            KnowledgePredicate::new("http.request", "url").unwrap(),
            EvidenceValue::Text("/very_long_relative_path_that_exceeds_max_url_bytes".into()),
        );
        let res = extractor.extract_from_evidence(&[e]);
        assert!(res.entities.is_empty());
    }

    #[test]
    fn relative_url_rejects_non_http_base() {
        let extractor = EntityExtractor::new();
        let non_http_subj = EntityId::new("endpoint:ftp://example.test/pub").unwrap();
        let e = ev_subj(
            non_http_subj,
            EvidenceKind::Http,
            KnowledgePredicate::new("http.request", "url").unwrap(),
            EvidenceValue::Text("/file.txt".into()),
        );
        let res = extractor.extract_from_evidence(&[e]);
        assert!(res.entities.is_empty());
    }

    #[test]
    fn absolute_and_relative_forms_produce_same_entity() {
        let extractor = EntityExtractor::new();
        let ev_rel = ev(
            EvidenceKind::Http,
            KnowledgePredicate::new("http.request", "url").unwrap(),
            EvidenceValue::Text("/api/user".into()),
        );
        let ev_abs = ev(
            EvidenceKind::Http,
            KnowledgePredicate::new("http.request", "url").unwrap(),
            EvidenceValue::Text("https://example.test/api/user".into()),
        );
        let res_rel = extractor.extract_from_evidence(&[ev_rel]);
        let res_abs = extractor.extract_from_evidence(&[ev_abs]);
        assert_eq!(res_rel.entities[0].id(), res_abs.entities[0].id());
    }

    #[test]
    fn relative_ipv6_endpoint_is_canonical() {
        let extractor = EntityExtractor::new();
        let v6_subj = EntityId::new("endpoint:http://[2001:db8::1]/api/v1").unwrap();
        let e = ev_subj(
            v6_subj,
            EvidenceKind::Http,
            KnowledgePredicate::new("http.request", "url").unwrap(),
            EvidenceValue::Text("/v2/users".into()),
        );
        let res = extractor.extract_from_evidence(&[e]);
        assert_eq!(
            res.entities[0].id().as_str(),
            "v1:endpoint:http://[2001:db8::1]/v2/users"
        );
    }

    #[test]
    fn malformed_header_name_produces_no_entity() {
        let extractor = EntityExtractor::new();
        let e = ev(
            EvidenceKind::Http,
            KnowledgePredicate::new("http.header", "bad-header name").unwrap(),
            EvidenceValue::Text("Bad Header Name: Value".into()),
        );
        let res = extractor.extract_from_evidence(&[e]);
        assert!(res.entities.is_empty());
    }

    #[test]
    fn limits_hard_ceiling_rejects_invalid_config() {
        assert!(SemanticExtractionLimits::new(0, 50, 50, 4096, 100, 2048).is_err());
        assert!(SemanticExtractionLimits::new(20_000, 50, 50, 4096, 100, 2048).is_err());
    }
}
