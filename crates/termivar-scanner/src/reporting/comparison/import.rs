//! Strict display-only import. No authoritative runtime type is constructed.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

use super::{
    ComparisonError, EvidenceMetadata, ImportedDocument, ImportedItem, ItemProjection,
    RemediationProjection, SourceMetadata, MAX_COMPARISON_INPUT_BYTES,
};

mod audits;

// Mirrors assessment_item.rs and assessment_report.rs without depending on the
// scanning feature or importing the authoritative projection types.
pub(super) const MAX_ITEMS: usize = 4_096;
pub(super) const MAX_DISPLAY_BYTES: usize = 1_024;
pub(super) const MAX_IDENTIFIER_BYTES: usize = 128;
pub(super) const MAX_REFERENCES: usize = 256;
const MAX_SUBJECTS: u64 = 1_024;
// Deepest current wire value: root/items/item/remediation/summary (root=0).
const MAX_JSON_DEPTH: usize = 4;
// The largest current object is the 21-field OpenAPI audit; allow no unbounded
// object collection while exact field inventories below reject unknown fields.
const MAX_OBJECT_FIELDS: usize = 21;

pub(super) fn parse(bytes: &[u8]) -> Result<ImportedDocument, ComparisonError> {
    if bytes.len() > MAX_COMPARISON_INPUT_BYTES {
        return Err(ComparisonError::InputLimitExceeded);
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = ValueSeed { depth: 0 }
        .deserialize(&mut decoder)
        .map_err(|_| ComparisonError::InvalidJson)?;
    decoder.end().map_err(|_| ComparisonError::InvalidJson)?;
    let root = object(&value)?;
    if root.get("schema").and_then(Value::as_str) != Some("venom-rendered-assessment/v1") {
        return Err(ComparisonError::UnsupportedDocument);
    }
    keys(
        root,
        &[
            "schema",
            "source_schema",
            "run_schema",
            "profile_schema",
            "profile",
            "status",
            "subject_count",
            "item_count",
            "items",
        ],
        &["authorization_review", "openapi_review", "rest_review"],
    )?;
    for (key, expected) in [
        ("source_schema", "venom-assessment-run/v1"),
        ("run_schema", "venom-run/v1"),
        ("profile_schema", "venom.scan-profile/v1"),
        ("profile", "web-review"),
        ("status", "complete"),
    ] {
        if string(root, key)? != expected {
            return Err(ComparisonError::UnsupportedDocument);
        }
    }
    let subject_count = number(root, "subject_count", MAX_SUBJECTS)?;
    check(subject_count > 0)?;
    let item_count = number(root, "item_count", MAX_ITEMS as u64)?;
    let wire_items = array(root, "items")?;
    check(item_count == wire_items.len() as u64)?;
    let mut items = BTreeMap::new();
    for value in wire_items {
        let (fingerprint, item) = item(value, subject_count)?;
        if items.insert(fingerprint, item).is_some() {
            return Err(ComparisonError::AmbiguousIdentity);
        }
    }
    let mut optional_audits = BTreeMap::new();
    for name in ["authorization_review", "openapi_review", "rest_review"] {
        if let Some(value) = root.get(name) {
            audits::validate(name, value, &items)?;
            optional_audits.insert(name.to_owned(), value.clone());
        }
    }
    // The existing renderer explicitly requires a REST audit for REST items.
    if items
        .values()
        .any(|item| item.capability_id == audits::REST_CAPABILITY)
    {
        check(optional_audits.contains_key("rest_review"))?;
    }
    Ok(ImportedDocument {
        metadata: SourceMetadata {
            sha256: format!("{:x}", Sha256::digest(bytes)),
            schema: string(root, "schema")?.to_owned(),
            source_schema: string(root, "source_schema")?.to_owned(),
            run_schema: string(root, "run_schema")?.to_owned(),
            profile_schema: string(root, "profile_schema")?.to_owned(),
            profile: string(root, "profile")?.to_owned(),
            status: string(root, "status")?.to_owned(),
            subject_count,
            item_count,
            optional_audits,
        },
        items,
    })
}

struct ValueSeed {
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for ValueSeed {
    type Value = Value;

    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
        if self.depth > MAX_JSON_DEPTH {
            return Err(de::Error::custom("document nesting limit"));
        }
        decoder.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for ValueSeed {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded report JSON")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        if value.len() > MAX_DISPLAY_BYTES {
            return Err(de::Error::custom("document string limit"));
        }
        Ok(Value::String(value.to_owned()))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut values: A) -> Result<Value, A::Error> {
        let mut array = Vec::new();
        while let Some(value) = values.next_element_seed(ValueSeed {
            depth: self.depth + 1,
        })? {
            if array.len() == MAX_ITEMS {
                return Err(de::Error::custom("document array limit"));
            }
            array.push(value);
        }
        Ok(Value::Array(array))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut fields: A) -> Result<Value, A::Error> {
        let mut object = Map::new();
        while let Some(key) = fields.next_key_seed(ValueSeed { depth: 0 })? {
            let key = key
                .as_str()
                .ok_or_else(|| de::Error::custom("document key type"))?;
            if key.len() > MAX_IDENTIFIER_BYTES || object.len() == MAX_OBJECT_FIELDS {
                return Err(de::Error::custom("document object limit"));
            }
            if object.contains_key(key) {
                return Err(de::Error::custom("duplicate document key"));
            }
            let value = fields.next_value_seed(ValueSeed {
                depth: self.depth + 1,
            })?;
            object.insert(key.to_owned(), value);
        }
        Ok(Value::Object(object))
    }
}

fn item(value: &Value, subject_count: u64) -> Result<(String, ImportedItem), ComparisonError> {
    let fields = object(value)?;
    keys(
        fields,
        &[
            "schema",
            "capability_id",
            "subject_reference",
            "title",
            "disposition",
            "claim_basis",
            "severity",
            "confidence_ppm",
            "fingerprint",
            "evidence_count",
            "redacted_summary",
            "category",
            "cwe",
            "remediation",
            "evidence_references",
            "control_evidence_references",
            "candidate_evidence_references",
            "case_reference",
            "outcome_reference",
            "verification_stage",
        ],
        &[],
    )?;
    check(string(fields, "schema")? == "venom-assessment-item/v1")?;
    let fingerprint = string(fields, "fingerprint")?;
    check(digest(fingerprint, "sha256:"))?;
    let capability_id = text(fields, "capability_id", MAX_IDENTIFIER_BYTES)?;
    let subject = reference(string(fields, "subject_reference")?, "subject")?;
    check(u64::from(subject) < subject_count)?;
    let evidence = evidence(fields)?;
    let claim_basis = token(
        fields,
        "claim_basis",
        &["observation", "differential", "verifier_transition"],
    )?;
    let disposition = token(
        fields,
        "disposition",
        &["informational", "needs_review", "confirmed"],
    )?;
    let direct = evidence.evidence_reference_count;
    let control = evidence.control_reference_count;
    let candidate = evidence.candidate_reference_count;
    let no_verifier = !evidence.case_present
        && !evidence.outcome_present
        && evidence.verification_stage.is_none();
    let valid_linkage = match claim_basis {
        "observation" => {
            disposition == "informational"
                && direct > 0
                && control == 0
                && candidate == 0
                && no_verifier
        },
        "differential" => {
            disposition == "needs_review"
                && ((direct == 1 && control == 0 && candidate == 0)
                    || (direct == 0 && control > 0 && candidate > 0))
                && no_verifier
        },
        "verifier_transition" => {
            disposition == "confirmed"
                && direct > 0
                && control == 0
                && candidate == 0
                && evidence.case_present
                && evidence.outcome_present
                && evidence.verification_stage.is_some()
        },
        _ => false,
    };
    check(valid_linkage)?;
    let remediation = object(required(fields, "remediation")?)?;
    keys(remediation, &["id", "summary"], &[])?;
    Ok((
        fingerprint.to_owned(),
        ImportedItem {
            capability_id: capability_id.to_owned(),
            projection: ItemProjection {
                title: text(fields, "title", MAX_DISPLAY_BYTES)?.to_owned(),
                category: text(fields, "category", MAX_DISPLAY_BYTES)?.to_owned(),
                disposition: disposition.to_owned(),
                claim_basis: claim_basis.to_owned(),
                severity: optional_token(
                    fields,
                    "severity",
                    &["info", "low", "medium", "high", "critical"],
                )?
                .map(str::to_owned),
                cwe: optional_text(fields, "cwe", MAX_IDENTIFIER_BYTES)?.map(str::to_owned),
                confidence_ppm: number(fields, "confidence_ppm", 1_000_000)? as u32,
                redacted_summary: text(fields, "redacted_summary", MAX_DISPLAY_BYTES)?.to_owned(),
                remediation: RemediationProjection {
                    id: text(remediation, "id", MAX_IDENTIFIER_BYTES)?.to_owned(),
                    summary: text(remediation, "summary", MAX_DISPLAY_BYTES)?.to_owned(),
                },
                evidence,
            },
        },
    ))
}

fn evidence(fields: &Map<String, Value>) -> Result<EvidenceMetadata, ComparisonError> {
    let mut unique = BTreeSet::new();
    let mut counts = [0; 3];
    for (index, key) in [
        "evidence_references",
        "control_evidence_references",
        "candidate_evidence_references",
    ]
    .into_iter()
    .enumerate()
    {
        let references = array(fields, key)?;
        check(references.len() <= MAX_REFERENCES)?;
        for value in references {
            let value = value.as_str().ok_or(ComparisonError::InvalidDocument)?;
            reference(value, "evidence")?;
            check(unique.insert(value))?;
        }
        counts[index] = references.len();
    }
    // The authoritative matched differential constructor caps the combined
    // control/candidate set at 256, not 256 independently for each side.
    let evidence_count = number(fields, "evidence_count", MAX_REFERENCES as u64)?;
    check(evidence_count == unique.len() as u64)?;
    let case = optional_text(fields, "case_reference", MAX_IDENTIFIER_BYTES)?;
    let outcome = optional_text(fields, "outcome_reference", MAX_IDENTIFIER_BYTES)?;
    if let Some(value) = case {
        reference(value, "case")?;
    }
    if let Some(value) = outcome {
        reference(value, "outcome")?;
    }
    Ok(EvidenceMetadata {
        evidence_count,
        evidence_reference_count: counts[0],
        control_reference_count: counts[1],
        candidate_reference_count: counts[2],
        case_present: case.is_some(),
        outcome_present: outcome.is_some(),
        verification_stage: optional_token(fields, "verification_stage", &["passive", "active"])?
            .map(str::to_owned),
    })
}

fn reference(value: &str, kind: &str) -> Result<u32, ComparisonError> {
    let suffix = value
        .strip_prefix(kind)
        .and_then(|value| value.strip_prefix('-'))
        .ok_or(ComparisonError::InvalidDocument)?;
    check(
        (4..=10).contains(&suffix.len())
            && suffix.bytes().all(|byte| byte.is_ascii_digit())
            && (suffix.len() == 4 || !suffix.starts_with('0')),
    )?;
    suffix.parse().map_err(|_| ComparisonError::InvalidDocument)
}

fn digest(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn object(value: &Value) -> Result<&Map<String, Value>, ComparisonError> {
    value.as_object().ok_or(ComparisonError::InvalidDocument)
}

fn keys(
    fields: &Map<String, Value>,
    required: &[&str],
    optional: &[&str],
) -> Result<(), ComparisonError> {
    check(
        required.iter().all(|key| fields.contains_key(*key))
            && fields
                .keys()
                .all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str())),
    )
}

fn required<'a>(fields: &'a Map<String, Value>, key: &str) -> Result<&'a Value, ComparisonError> {
    fields.get(key).ok_or(ComparisonError::InvalidDocument)
}

fn string<'a>(fields: &'a Map<String, Value>, key: &str) -> Result<&'a str, ComparisonError> {
    required(fields, key)?
        .as_str()
        .ok_or(ComparisonError::InvalidDocument)
}

fn text<'a>(
    fields: &'a Map<String, Value>,
    key: &str,
    limit: usize,
) -> Result<&'a str, ComparisonError> {
    let value = string(fields, key)?;
    check(!value.is_empty() && value.len() <= limit)?;
    Ok(value)
}

fn optional_text<'a>(
    fields: &'a Map<String, Value>,
    key: &str,
    limit: usize,
) -> Result<Option<&'a str>, ComparisonError> {
    if required(fields, key)?.is_null() {
        Ok(None)
    } else {
        text(fields, key, limit).map(Some)
    }
}

fn token<'a>(
    fields: &'a Map<String, Value>,
    key: &str,
    allowed: &[&str],
) -> Result<&'a str, ComparisonError> {
    let value = string(fields, key)?;
    check(allowed.contains(&value))?;
    Ok(value)
}

fn optional_token<'a>(
    fields: &'a Map<String, Value>,
    key: &str,
    allowed: &[&str],
) -> Result<Option<&'a str>, ComparisonError> {
    let value = optional_text(fields, key, MAX_IDENTIFIER_BYTES)?;
    check(value.is_none_or(|value| allowed.contains(&value)))?;
    Ok(value)
}

fn number(fields: &Map<String, Value>, key: &str, limit: u64) -> Result<u64, ComparisonError> {
    let value = required(fields, key)?
        .as_u64()
        .ok_or(ComparisonError::InvalidDocument)?;
    check(value <= limit)?;
    Ok(value)
}

fn boolean(fields: &Map<String, Value>, key: &str) -> Result<bool, ComparisonError> {
    required(fields, key)?
        .as_bool()
        .ok_or(ComparisonError::InvalidDocument)
}

fn optional_boolean(
    fields: &Map<String, Value>,
    key: &str,
) -> Result<Option<bool>, ComparisonError> {
    if required(fields, key)?.is_null() {
        Ok(None)
    } else {
        boolean(fields, key).map(Some)
    }
}

fn array<'a>(fields: &'a Map<String, Value>, key: &str) -> Result<&'a Vec<Value>, ComparisonError> {
    required(fields, key)?
        .as_array()
        .ok_or(ComparisonError::InvalidDocument)
}

fn check(condition: bool) -> Result<(), ComparisonError> {
    if condition {
        Ok(())
    } else {
        Err(ComparisonError::InvalidDocument)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_visitor_rejects_non_string_keys_and_helpers_reject_missing_fields() {
        let fields = serde::de::value::MapDeserializer::<_, serde::de::value::Error>::new(
            [(1_u64, 2_u64)].into_iter(),
        );
        assert!(ValueSeed { depth: 0 }.deserialize(fields).is_err());
        assert_eq!(
            required(&Map::new(), "missing"),
            Err(ComparisonError::InvalidDocument)
        );
    }
}
