//! Bounded reduction of TLS metadata attached to existing validated responses.

use std::{
    sync::{Arc, Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};
use x509_parser::{
    certificate::X509CertificateParser,
    extensions::{GeneralName, SubjectAlternativeName},
    nom::Parser,
    oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME,
    prelude::FromDer,
};

/// Schema of the immutable TLS observation audit.
pub const TLS_OBSERVATION_AUDIT_SCHEMA: &str = "security.tls-observation-audit/v1";
/// Policy governing observation of an existing validated connection.
pub const TLS_OBSERVATION_POLICY_ID: &str = "termivar.existing-connection-tls-observation/v1";
/// Value used for facts that reqwest's public metadata surface does not expose.
pub const TLS_OBSERVATION_BACKEND_LIMIT: &str = "not_exposed_by_backend";
/// Revocation scope of this passive observer.
pub const TLS_OBSERVATION_REVOCATION_STATUS: &str = "not_checked";
/// Scope of the standard transport-validation statement.
pub const TLS_OBSERVATION_VALIDATION_SCOPE: &str = "successful_https_response_connection/v1";
/// Privacy-preserving source scope for every retained observation.
pub const TLS_OBSERVATION_SOURCE_SCOPE: &str = "assessment_exact_origin_existing_connections/v1";
/// Assurance attached to the local wall clock used for validity classification.
pub const TLS_OBSERVATION_CLOCK_ASSURANCE: &str = "local_system_clock_not_independently_verified";

/// Maximum peer leaf DER bytes inspected per response.
pub const MAX_TLS_LEAF_CERTIFICATE_BYTES: usize = 64 * 1024;
/// Maximum unique peer leaves retained per assessment.
pub const MAX_TLS_RETAINED_LEAF_OBSERVATIONS: usize = 16;
/// Maximum SAN entries classified per retained peer leaf.
pub const MAX_TLS_SAN_ENTRIES_PER_CERTIFICATE: usize = 256;
/// Maximum shallow X.509 extension records admitted per peer leaf.
pub const MAX_TLS_CERTIFICATE_EXTENSIONS: usize = 64;
/// Maximum raw Subject Alternative Name extension bytes parsed per peer leaf.
pub const MAX_TLS_SUBJECT_ALTERNATIVE_NAME_BYTES: usize = 16 * 1024;

/// Scheme selected by the assessment authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsObservationTargetScheme {
    /// Plain HTTP, for which TLS is not applicable.
    Http,
    /// HTTPS through the ordinary verified transport path.
    Https,
    /// A scheme outside the web-assessment contract.
    Other,
}

impl TlsObservationTargetScheme {
    pub(crate) fn from_scheme(value: &str) -> Self {
        match value {
            "http" => Self::Http,
            "https" => Self::Https,
            _ => Self::Other,
        }
    }

    /// Stable wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Other => "other",
        }
    }
}

/// Relationship between a leaf's validity window and its observation instant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsCertificateTimeStatus {
    /// Observation fell within the declared validity window.
    ValidAtObservation,
    /// Observation preceded the declared validity window.
    NotYetValidAtObservation,
    /// Observation followed the declared validity window.
    ExpiredAtObservation,
}

impl TlsCertificateTimeStatus {
    /// Stable wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ValidAtObservation => "valid_at_observation",
            Self::NotYetValidAtObservation => "not_yet_valid_at_observation",
            Self::ExpiredAtObservation => "expired_at_observation",
        }
    }
}

/// Value-safe reduction of one unique parsed peer leaf certificate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsLeafObservation {
    sha256: String,
    byte_length: u64,
    not_before_epoch_seconds: i64,
    not_after_epoch_seconds: i64,
    observed_at_epoch_seconds: i64,
    dns_san_count: u16,
    ip_san_count: u16,
    other_san_count: u16,
    san_count_truncated: bool,
    certificate_time_status: TlsCertificateTimeStatus,
    response_occurrence_count: u64,
}

impl TlsLeafObservation {
    /// Full lower-case SHA-256 of the exact observed leaf DER bytes.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    /// Exact observed leaf DER byte length.
    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }
    /// Declared not-before time as Unix epoch seconds.
    pub const fn not_before_epoch_seconds(&self) -> i64 {
        self.not_before_epoch_seconds
    }
    /// Declared not-after time as Unix epoch seconds.
    pub const fn not_after_epoch_seconds(&self) -> i64 {
        self.not_after_epoch_seconds
    }
    /// First observation time as Unix epoch seconds.
    pub const fn observed_at_epoch_seconds(&self) -> i64 {
        self.observed_at_epoch_seconds
    }
    /// Number of classified DNS SANs, without retaining their values.
    pub const fn dns_san_count(&self) -> u16 {
        self.dns_san_count
    }
    /// Number of classified IP SANs, without retaining their values.
    pub const fn ip_san_count(&self) -> u16 {
        self.ip_san_count
    }
    /// Number of classified SANs of all other kinds.
    pub const fn other_san_count(&self) -> u16 {
        self.other_san_count
    }
    /// Whether SAN classification stopped at its explicit ceiling.
    pub const fn san_count_truncated(&self) -> bool {
        self.san_count_truncated
    }
    /// Validity-window relationship at first observation.
    pub const fn certificate_time_status(&self) -> TlsCertificateTimeStatus {
        self.certificate_time_status
    }
    /// Successful HTTPS responses carrying this same leaf identity.
    pub const fn response_occurrence_count(&self) -> u64 {
        self.response_occurrence_count
    }
    /// Whether the normal transport accepted the response connection.
    pub const fn standard_transport_validation_succeeded(&self) -> bool {
        true
    }
}

/// Immutable assessment-level passive TLS audit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebAssessmentTlsObservationAudit {
    target_scheme: TlsObservationTargetScheme,
    successful_https_response_count: u64,
    plaintext_response_count: u64,
    tls_info_unavailable_count: u64,
    malformed_certificate_count: u64,
    certificate_limit_rejection_count: u64,
    unretained_leaf_response_count: u64,
    leaf_observations: Vec<TlsLeafObservation>,
}

impl WebAssessmentTlsObservationAudit {
    /// Audit schema.
    pub const fn schema(&self) -> &'static str {
        TLS_OBSERVATION_AUDIT_SCHEMA
    }
    /// Observation policy.
    pub const fn policy(&self) -> &'static str {
        TLS_OBSERVATION_POLICY_ID
    }
    /// An audit exists only when the capability was selected.
    pub const fn selected(&self) -> bool {
        true
    }
    /// This capability dispatches no additional requests.
    pub const fn additional_request_count(&self) -> u64 {
        0
    }
    /// Assessment target scheme.
    pub const fn target_scheme(&self) -> TlsObservationTargetScheme {
        self.target_scheme
    }
    /// Source scope shared by all responses represented by this audit.
    pub const fn observation_source_scope(&self) -> &'static str {
        TLS_OBSERVATION_SOURCE_SCOPE
    }
    /// Assurance for the wall clock used by observation-time classifications.
    pub const fn observation_clock_assurance(&self) -> &'static str {
        TLS_OBSERVATION_CLOCK_ASSURANCE
    }
    /// Successful HTTPS responses observed after ordinary validation.
    pub const fn successful_https_response_count(&self) -> u64 {
        self.successful_https_response_count
    }
    /// Successful plain HTTP responses, for which TLS is not applicable.
    pub const fn plaintext_response_count(&self) -> u64 {
        self.plaintext_response_count
    }
    /// HTTPS successes for which the backend exposed no leaf information.
    pub const fn tls_info_unavailable_count(&self) -> u64 {
        self.tls_info_unavailable_count
    }
    /// Leaf values rejected because they were not one exact parsed certificate.
    pub const fn malformed_certificate_count(&self) -> u64 {
        self.malformed_certificate_count
    }
    /// Leaf values rejected by the certificate, extension, or SAN ceilings.
    pub const fn certificate_limit_rejection_count(&self) -> u64 {
        self.certificate_limit_rejection_count
    }
    /// Parsed leaf-bearing responses omitted after the unique-leaf ceiling.
    pub const fn unretained_leaf_response_count(&self) -> u64 {
        self.unretained_leaf_response_count
    }
    /// Unique retained leaves in first-observation order.
    pub fn leaf_observations(&self) -> &[TlsLeafObservation] {
        &self.leaf_observations
    }
    /// Negotiated TLS protocol is not exposed by this backend seam.
    pub const fn protocol(&self) -> &'static str {
        TLS_OBSERVATION_BACKEND_LIMIT
    }
    /// Negotiated cipher suite is not exposed by this backend seam.
    pub const fn cipher_suite(&self) -> &'static str {
        TLS_OBSERVATION_BACKEND_LIMIT
    }
    /// Negotiated ALPN protocol is not exposed by this backend seam.
    pub const fn alpn_protocol(&self) -> &'static str {
        TLS_OBSERVATION_BACKEND_LIMIT
    }
    /// The full peer or validated chain is not exposed by this backend seam.
    pub const fn full_chain(&self) -> &'static str {
        TLS_OBSERVATION_BACKEND_LIMIT
    }
    /// Connection reuse is not exposed and cannot be inferred from a repeated leaf.
    pub const fn connection_reuse(&self) -> &'static str {
        TLS_OBSERVATION_BACKEND_LIMIT
    }
    /// Session resumption is not exposed by this backend seam.
    pub const fn session_resumption(&self) -> &'static str {
        TLS_OBSERVATION_BACKEND_LIMIT
    }
    /// Full-versus-resumed handshake kind is not exposed by this backend seam.
    pub const fn handshake_kind(&self) -> &'static str {
        TLS_OBSERVATION_BACKEND_LIMIT
    }
    /// Revocation status for this capability.
    pub const fn revocation(&self) -> &'static str {
        TLS_OBSERVATION_REVOCATION_STATUS
    }
    /// Scope of the standard transport-validation statement.
    pub const fn standard_transport_validation_scope(&self) -> &'static str {
        TLS_OBSERVATION_VALIDATION_SCOPE
    }
}

#[derive(Default)]
struct TlsObservationState {
    successful_https_response_count: u64,
    plaintext_response_count: u64,
    tls_info_unavailable_count: u64,
    malformed_certificate_count: u64,
    certificate_limit_rejection_count: u64,
    unretained_leaf_response_count: u64,
    leaf_observations: Vec<TlsLeafObservation>,
}

/// Shared assessment-owned sink used by each selected broker connection pool.
#[derive(Clone)]
pub(crate) struct TlsObservationCollector {
    target_scheme: TlsObservationTargetScheme,
    state: Arc<Mutex<TlsObservationState>>,
}

impl TlsObservationCollector {
    pub(crate) fn new(target_scheme: &str) -> Self {
        Self {
            target_scheme: TlsObservationTargetScheme::from_scheme(target_scheme),
            state: Arc::new(Mutex::new(TlsObservationState::default())),
        }
    }

    pub(crate) fn observe_plaintext_response(&self) {
        let mut state = self.state();
        state.plaintext_response_count = state.plaintext_response_count.saturating_add(1);
    }

    pub(crate) fn observe_https_response(&self, peer_leaf_der: Option<&[u8]>) {
        self.observe_https_response_at(peer_leaf_der, epoch_seconds(SystemTime::now()));
    }

    fn observe_https_response_at(&self, peer_leaf_der: Option<&[u8]>, observed_at: i64) {
        let mut state = self.state();
        state.successful_https_response_count =
            state.successful_https_response_count.saturating_add(1);
        let Some(der) = peer_leaf_der else {
            state.tls_info_unavailable_count = state.tls_info_unavailable_count.saturating_add(1);
            return;
        };
        if der.len() > MAX_TLS_LEAF_CERTIFICATE_BYTES {
            state.certificate_limit_rejection_count =
                state.certificate_limit_rejection_count.saturating_add(1);
            return;
        }
        let observation = match parse_leaf(der, observed_at) {
            Ok(observation) => observation,
            Err(LeafParseError::Malformed) => {
                state.malformed_certificate_count =
                    state.malformed_certificate_count.saturating_add(1);
                return;
            },
            Err(LeafParseError::LimitRejected) => {
                state.certificate_limit_rejection_count =
                    state.certificate_limit_rejection_count.saturating_add(1);
                return;
            },
        };
        if let Some(existing) = state.leaf_observations.iter_mut().find(|existing| {
            existing.sha256 == observation.sha256 && existing.byte_length == observation.byte_length
        }) {
            existing.response_occurrence_count =
                existing.response_occurrence_count.saturating_add(1);
        } else if state.leaf_observations.len() < MAX_TLS_RETAINED_LEAF_OBSERVATIONS {
            state.leaf_observations.push(observation);
        } else {
            state.unretained_leaf_response_count =
                state.unretained_leaf_response_count.saturating_add(1);
        }
    }

    pub(crate) fn audit(&self) -> WebAssessmentTlsObservationAudit {
        let state = self.state();
        WebAssessmentTlsObservationAudit {
            target_scheme: self.target_scheme,
            successful_https_response_count: state.successful_https_response_count,
            plaintext_response_count: state.plaintext_response_count,
            tls_info_unavailable_count: state.tls_info_unavailable_count,
            malformed_certificate_count: state.malformed_certificate_count,
            certificate_limit_rejection_count: state.certificate_limit_rejection_count,
            unretained_leaf_response_count: state.unretained_leaf_response_count,
            leaf_observations: state.leaf_observations.clone(),
        }
    }

    #[cfg(test)]
    pub(crate) fn shares_state_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }

    fn state(&self) -> MutexGuard<'_, TlsObservationState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LeafParseError {
    Malformed,
    LimitRejected,
}

fn parse_leaf(der: &[u8], observed_at: i64) -> Result<TlsLeafObservation, LeafParseError> {
    let mut parser = X509CertificateParser::new().with_deep_parse_extensions(false);
    let (remainder, certificate) = parser.parse(der).map_err(|_| LeafParseError::Malformed)?;
    if !remainder.is_empty() {
        return Err(LeafParseError::Malformed);
    }
    let extensions = certificate.extensions();
    if extensions.len() > MAX_TLS_CERTIFICATE_EXTENSIONS {
        return Err(LeafParseError::LimitRejected);
    }
    let not_before = certificate.validity().not_before.timestamp();
    let not_after = certificate.validity().not_after.timestamp();
    if not_after < not_before {
        return Err(LeafParseError::Malformed);
    }
    let raw_san = select_unique_san_value(
        extensions.len(),
        extensions
            .iter()
            .filter(|extension| extension.oid == OID_X509_EXT_SUBJECT_ALT_NAME)
            .map(|extension| extension.value),
    )?;
    let (dns_san_count, ip_san_count, other_san_count, san_count_truncated) =
        classify_san(raw_san)?;
    let certificate_time_status = if observed_at < not_before {
        TlsCertificateTimeStatus::NotYetValidAtObservation
    } else if observed_at > not_after {
        TlsCertificateTimeStatus::ExpiredAtObservation
    } else {
        TlsCertificateTimeStatus::ValidAtObservation
    };
    Ok(TlsLeafObservation {
        sha256: format!("{:x}", Sha256::digest(der)),
        byte_length: u64::try_from(der.len()).unwrap_or(u64::MAX),
        not_before_epoch_seconds: not_before,
        not_after_epoch_seconds: not_after,
        observed_at_epoch_seconds: observed_at,
        dns_san_count,
        ip_san_count,
        other_san_count,
        san_count_truncated,
        certificate_time_status,
        response_occurrence_count: 1,
    })
}

fn select_unique_san_value<'a>(
    extension_count: usize,
    mut san_values: impl Iterator<Item = &'a [u8]>,
) -> Result<Option<&'a [u8]>, LeafParseError> {
    if extension_count > MAX_TLS_CERTIFICATE_EXTENSIONS {
        return Err(LeafParseError::LimitRejected);
    }
    let first = san_values.next();
    if san_values.next().is_some() {
        return Err(LeafParseError::Malformed);
    }
    Ok(first)
}

fn classify_san(raw_san: Option<&[u8]>) -> Result<(u16, u16, u16, bool), LeafParseError> {
    let Some(raw_san) = raw_san else {
        return Ok((0, 0, 0, false));
    };
    if raw_san.len() > MAX_TLS_SUBJECT_ALTERNATIVE_NAME_BYTES {
        return Err(LeafParseError::LimitRejected);
    }
    let (remainder, san) =
        SubjectAlternativeName::from_der(raw_san).map_err(|_| LeafParseError::Malformed)?;
    if !remainder.is_empty() {
        return Err(LeafParseError::Malformed);
    }
    let mut dns = 0_u16;
    let mut ip = 0_u16;
    let mut other = 0_u16;
    let mut truncated = false;
    for (index, name) in san.general_names.iter().enumerate() {
        if index >= MAX_TLS_SAN_ENTRIES_PER_CERTIFICATE {
            truncated = true;
            break;
        }
        match name {
            GeneralName::DNSName(_) => dns = dns.saturating_add(1),
            GeneralName::IPAddress(value) if matches!(value.len(), 4 | 16) => {
                ip = ip.saturating_add(1);
            },
            _ => other = other.saturating_add(1),
        }
    }
    Ok((dns, ip, other, truncated))
}

fn epoch_seconds(now: SystemTime) -> i64 {
    match now.duration_since(UNIX_EPOCH) {
        Ok(value) => i64::try_from(value.as_secs()).unwrap_or(i64::MAX),
        Err(value) => -i64::try_from(value.duration().as_secs()).unwrap_or(i64::MAX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    const EXPIRED_LEAF: &str = concat!(
        "MIIFWzCCBEOgAwIBAgISAyBIAwu7NBD5CTxX8suDCMgFMA0GCSqGSIb3DQEBCwUAMEox",
        "CzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQDExpMZXQn",
        "cyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xOTA3MTIxMTEyMzBaFw0xOTEwMTAxMTEy",
        "MzBaMB0xGzAZBgNVBAMTEmxpc3RzLmZvci1vdXIuaW5mbzCCASIwDQYJKoZIhvcNAQEB",
        "BQADggEPADCCAQoCggEBAMVoti34X46DaI2nX24C+aZ2OfkmhKbidiXiRTon1MLSMGl1",
        "oNW9MyRyYYCzP4j6DNKChJnr8ZnVShh2oZD+yHWP9lpnXMGkbsUxejRMU9hnaAB50pXR",
        "IDAzavkVFCguFlJ8nKkv/Y1Avlw7tc2aZOd3lOZBEr8gJ8mRDGqqsNU+Z12I6slEstz",
        "GMpsq6AewCVw4lMjdWWgugzUrxQTRAsG87on6gOiQH2cMODN3L7Fq4KOLQIjb3/luQh",
        "AQhpdKmEGFLin3c+f5or3thCDuwwDtOU1lZf+8t9S8pZPLrZrIs6H2xjXqCRuUY7iRN",
        "bO18Ukc6rlDYhBj9LT+cpmBbHECAwEAAaOCAmYwggJiMA4GA1UdDwEB/wQEAwIFoDAd",
        "BgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4E",
        "FgQUJj2pvRtl3GloH3He6FX1ds3X0VEwHwYDVR0jBBgwFoAUqEpqYwR93brm0Tm3pkVl",
        "7/Oo7KEwbwYIKwYBBQUHAQEEYzBhMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcC5pbnQt",
        "eDMubGV0c2VuY3J5cHQub3JnMC8GCCsGAQUFBzAChiNodHRwOi8vY2VydC5pbnQteDMu",
        "bGV0c2VuY3J5cHQub3JnLzAdBgNVHREEFjAUghJsaXN0cy5mb3Itb3VyLmluZm8wTAYD",
        "VR0gBEUwQzAIBgZngQwBAgEwNwYLKwYBBAGC3xMBAQEwKDAmBggrBgEFBQcCARYaaHR0",
        "cDovL2Nwcy5sZXRzZW5jcnlwdC5vcmcwggEDBgorBgEEAdZ5AgQCBIH0BIHxAO8AdgAp",
        "PFGWVMg5ZbqqUPxYB9S3b79Yeily3KTDDPTlRUf0eAAAAWvmGV7yAAAEAwBHMEUCICQL",
        "2Sm14aCMLxX9a9RbySgyBfichMRdbu6QA2Mbrl4eAiEA1vgJ7snqUWCgoqEE3SEfK3io",
        "MopzWBsPvG6LdCuCMRAAdQBvU3asMfAxGdiZAKRRFf93FRwR2QLBACkGjbIImjfZEwAA",
        "AWvmGV9oAAAEAwBGMEQCIExGqw3Lo0nSCyUuTRf92FgGASwWYji5UGnXuYnpJrAvAiBw",
        "8AWVag8fzZ4ogAhY9EFRNdLrUcBjStipL888vyuxKzANBgkqhkiG9w0BAQsFAAOCAQEA",
        "F8BBLDvSWZg57B6aDtzfUTSGetCYs3k0vJqCJlL+Pz7/UruCSsojQzp5R6jvvgYQ83Ma",
        "Idwe2mgt+OCQB5v7ylctyBzBmYIw9nPnxEC7HlcJL2K/k5ZjJFRnv4kV1Si8+TIpEAV0",
        "ksf39KGKemG8kGi4GXV1v03zSv0p8aCarpuoSKBJ4qlB0CvmS2MqV4KnzO0O2h0c/ZQ4",
        "jg7l53eiN7VPdRMMO1DRw+MaW6I/hEZp+oZQ7hhKXgKUBvF4IGwyrfyIZ8AeWKG4IP98",
        "COgyRbz7qtrAVevRKCM0ZC2t04A2Fcix40FKEeiE093Aj3cweMYxNLPgwgQP8Xu3kA5QEw=="
    );

    fn der_length(length: usize) -> Vec<u8> {
        if length < 128 {
            return vec![length as u8];
        }
        let bytes = length.to_be_bytes();
        let first = bytes.iter().position(|byte| *byte != 0).unwrap();
        let significant = &bytes[first..];
        let mut encoded = vec![0x80 | significant.len() as u8];
        encoded.extend_from_slice(significant);
        encoded
    }

    fn san_sequence(entries: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut content = Vec::new();
        for (tag, value) in entries {
            content.push(*tag);
            content.extend(der_length(value.len()));
            content.extend(value);
        }
        let mut encoded = vec![0x30];
        encoded.extend(der_length(content.len()));
        encoded.extend(content);
        encoded
    }

    #[test]
    fn reduces_and_deduplicates_leaf_without_names() {
        let der = STANDARD.decode(EXPIRED_LEAF).unwrap();
        let collector = TlsObservationCollector::new("https");
        collector.observe_https_response_at(Some(&der), 1_700_000_000);
        collector.observe_https_response_at(Some(&der), 1_700_000_001);
        let audit = collector.audit();
        assert_eq!(audit.successful_https_response_count(), 2);
        assert_eq!(audit.leaf_observations().len(), 1);
        let leaf = &audit.leaf_observations()[0];
        assert_eq!(leaf.byte_length(), 1_375);
        assert_eq!(leaf.dns_san_count(), 1);
        assert_eq!(leaf.response_occurrence_count(), 2);
        assert_eq!(
            leaf.certificate_time_status(),
            TlsCertificateTimeStatus::ExpiredAtObservation
        );
        assert!(!format!("{audit:?}").contains("lists.for-our.info"));
        assert_eq!(audit.connection_reuse(), TLS_OBSERVATION_BACKEND_LIMIT);
        assert_eq!(audit.session_resumption(), TLS_OBSERVATION_BACKEND_LIMIT);
        assert_eq!(audit.handshake_kind(), TLS_OBSERVATION_BACKEND_LIMIT);
    }

    #[test]
    fn unavailable_malformed_oversized_and_plaintext_are_distinct() {
        let collector = TlsObservationCollector::new("https");
        collector.observe_plaintext_response();
        collector.observe_https_response_at(None, 0);
        collector.observe_https_response_at(Some(b"not a certificate"), 0);
        collector.observe_https_response_at(Some(&vec![0; MAX_TLS_LEAF_CERTIFICATE_BYTES + 1]), 0);
        let audit = collector.audit();
        assert_eq!(audit.plaintext_response_count(), 1);
        assert_eq!(audit.successful_https_response_count(), 3);
        assert_eq!(audit.tls_info_unavailable_count(), 1);
        assert_eq!(audit.malformed_certificate_count(), 1);
        assert_eq!(audit.certificate_limit_rejection_count(), 1);
        assert_eq!(audit.alpn_protocol(), TLS_OBSERVATION_BACKEND_LIMIT);
        assert_eq!(audit.session_resumption(), TLS_OBSERVATION_BACKEND_LIMIT);
    }

    #[test]
    fn clones_share_one_bounded_state() {
        let first = TlsObservationCollector::new("http");
        let second = first.clone();
        assert!(first.shares_state_with(&second));
        first.observe_plaintext_response();
        second.observe_plaintext_response();
        assert_eq!(first.audit().plaintext_response_count(), 2);
        assert_eq!(second.audit().target_scheme().as_str(), "http");
    }

    #[test]
    fn shallow_extension_and_san_work_bounds_reject_mutations() {
        let san = san_sequence(&[(0x82, b"example.test".to_vec())]);
        assert!(select_unique_san_value(
            MAX_TLS_CERTIFICATE_EXTENSIONS,
            std::iter::once(san.as_slice())
        )
        .is_ok());
        assert_eq!(
            select_unique_san_value(MAX_TLS_CERTIFICATE_EXTENSIONS + 1, std::iter::empty()),
            Err(LeafParseError::LimitRejected)
        );
        assert_eq!(
            select_unique_san_value(2, [san.as_slice(), san.as_slice()].into_iter()),
            Err(LeafParseError::Malformed)
        );
        assert_eq!(
            classify_san(Some(&vec![0; MAX_TLS_SUBJECT_ALTERNATIVE_NAME_BYTES + 1])),
            Err(LeafParseError::LimitRejected)
        );

        let entries = (0..=MAX_TLS_SAN_ENTRIES_PER_CERTIFICATE)
            .map(|_| (0x82, b"x".to_vec()))
            .collect::<Vec<_>>();
        assert_eq!(
            classify_san(Some(&san_sequence(&entries))),
            Ok((MAX_TLS_SAN_ENTRIES_PER_CERTIFICATE as u16, 0, 0, true))
        );

        let invalid_ip = san_sequence(&[(0x87, vec![127, 0, 1])]);
        assert_eq!(classify_san(Some(&invalid_ip)), Ok((0, 0, 1, false)));
        let mut trailing = san;
        trailing.push(0);
        assert_eq!(
            classify_san(Some(&trailing)),
            Err(LeafParseError::Malformed)
        );
    }
}
