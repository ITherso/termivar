//! Robust, deterministic defense-product fingerprinting from response signals.
//!
//! This module only *observes*. It infers which defensive product most likely
//! produced a response from header and body signals; it never selects a payload
//! or an evasion technique. Matching is case-insensitive and substring-based, so
//! it does not depend on exact header strings the way a brittle equality check
//! would.

/// Maximum number of response-body bytes scanned for a fingerprint signal.
///
/// Fingerprinting reads only a bounded prefix so a large body cannot turn one
/// observation into unbounded work.
pub const MAX_FINGERPRINT_BODY_SCAN_BYTES: usize = 16 * 1024;

/// Defensive product inferred from response signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DefenseProduct {
    /// Cloudflare edge and WAF.
    Cloudflare,
    /// AWS WAF or an AWS edge in front of the origin.
    AwsWaf,
    /// ModSecurity or a ModSecurity-based rule set.
    ModSecurity,
    /// Akamai edge and Kona Site Defender.
    Akamai,
    /// Imperva / Incapsula.
    Imperva,
    /// F5 BIG-IP ASM.
    F5BigIp,
    /// Barracuda Web Application Firewall.
    Barracuda,
    /// Fortinet FortiWeb.
    Fortinet,
    /// Sucuri CloudProxy.
    Sucuri,
    /// Wordfence for WordPress.
    Wordfence,
}

impl DefenseProduct {
    /// Returns the stable, human-readable product name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cloudflare => "Cloudflare",
            Self::AwsWaf => "AWS WAF",
            Self::ModSecurity => "ModSecurity",
            Self::Akamai => "Akamai",
            Self::Imperva => "Imperva",
            Self::F5BigIp => "F5 BIG-IP ASM",
            Self::Barracuda => "Barracuda",
            Self::Fortinet => "Fortinet FortiWeb",
            Self::Sucuri => "Sucuri",
            Self::Wordfence => "Wordfence",
        }
    }
}

/// Confidence that a fingerprint reflects the named product.
///
/// Ordering is meaningful: a stronger match supersedes a weaker one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FingerprintConfidence {
    /// A single ambiguous signal that could also occur without the product.
    Weak,
    /// A signal that usually, but not exclusively, indicates the product.
    Probable,
    /// A signal that is specific to the product.
    Strong,
}

/// One product fingerprint together with the signal that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefenseFingerprint {
    product: DefenseProduct,
    confidence: FingerprintConfidence,
    signal: &'static str,
}

impl DefenseFingerprint {
    pub(crate) const fn from_assessment_hint(
        product: DefenseProduct,
        confidence: FingerprintConfidence,
    ) -> Self {
        Self {
            product,
            confidence,
            signal: "assessment:fingerprint-hint",
        }
    }

    /// Returns the inferred product.
    pub const fn product(&self) -> DefenseProduct {
        self.product
    }

    /// Returns how strongly the signal indicates the product.
    pub const fn confidence(&self) -> FingerprintConfidence {
        self.confidence
    }

    /// Returns a stable label for the signal that produced this fingerprint.
    pub const fn signal(&self) -> &'static str {
        self.signal
    }
}

/// A single, deterministic fingerprint rule.
enum Match {
    /// A header with this lowercase name is present with any value.
    HeaderPresent(&'static str),
    /// A header with this lowercase name has a value containing `needle`.
    HeaderValueContains(&'static str, &'static str),
    /// Any `set-cookie` header value contains `needle`.
    CookieContains(&'static str),
    /// The scanned body prefix contains `needle`.
    BodyContains(&'static str),
}

struct Rule {
    product: DefenseProduct,
    confidence: FingerprintConfidence,
    signal: &'static str,
    matcher: Match,
}

/// Deterministic rule table. Needles are lowercase; matching lowercases inputs.
///
/// AWS signals are intentionally conservative: an Amazon request id or S3 server
/// banner indicates Amazon infrastructure, not necessarily a WAF, so it is only
/// ever a weak signal.
const RULES: &[Rule] = &[
    Rule {
        product: DefenseProduct::Cloudflare,
        confidence: FingerprintConfidence::Strong,
        signal: "header:cf-ray",
        matcher: Match::HeaderPresent("cf-ray"),
    },
    Rule {
        product: DefenseProduct::Cloudflare,
        confidence: FingerprintConfidence::Strong,
        signal: "header:server=cloudflare",
        matcher: Match::HeaderValueContains("server", "cloudflare"),
    },
    Rule {
        product: DefenseProduct::Cloudflare,
        confidence: FingerprintConfidence::Probable,
        signal: "body:attention-required",
        matcher: Match::BodyContains("attention required"),
    },
    Rule {
        product: DefenseProduct::AwsWaf,
        confidence: FingerprintConfidence::Probable,
        signal: "header:x-amzn-waf",
        matcher: Match::HeaderPresent("x-amzn-waf-action"),
    },
    Rule {
        product: DefenseProduct::AwsWaf,
        confidence: FingerprintConfidence::Weak,
        signal: "header:x-amzn-requestid",
        matcher: Match::HeaderPresent("x-amzn-requestid"),
    },
    Rule {
        product: DefenseProduct::ModSecurity,
        confidence: FingerprintConfidence::Strong,
        signal: "header:server=mod_security",
        matcher: Match::HeaderValueContains("server", "mod_security"),
    },
    Rule {
        product: DefenseProduct::ModSecurity,
        confidence: FingerprintConfidence::Strong,
        signal: "body:mod_security",
        matcher: Match::BodyContains("mod_security"),
    },
    Rule {
        product: DefenseProduct::Akamai,
        confidence: FingerprintConfidence::Strong,
        signal: "header:server=akamaighost",
        matcher: Match::HeaderValueContains("server", "akamaighost"),
    },
    Rule {
        product: DefenseProduct::Imperva,
        confidence: FingerprintConfidence::Strong,
        signal: "header:x-iinfo",
        matcher: Match::HeaderPresent("x-iinfo"),
    },
    Rule {
        product: DefenseProduct::Imperva,
        confidence: FingerprintConfidence::Strong,
        signal: "cookie:incap_ses",
        matcher: Match::CookieContains("incap_ses"),
    },
    Rule {
        product: DefenseProduct::F5BigIp,
        confidence: FingerprintConfidence::Strong,
        signal: "cookie:bigipserver",
        matcher: Match::CookieContains("bigipserver"),
    },
    Rule {
        product: DefenseProduct::Barracuda,
        confidence: FingerprintConfidence::Strong,
        signal: "cookie:barra_counter",
        matcher: Match::CookieContains("barra_counter_session"),
    },
    Rule {
        product: DefenseProduct::Fortinet,
        confidence: FingerprintConfidence::Strong,
        signal: "cookie:fortiwafsid",
        matcher: Match::CookieContains("fortiwafsid"),
    },
    Rule {
        product: DefenseProduct::Sucuri,
        confidence: FingerprintConfidence::Strong,
        signal: "header:x-sucuri-id",
        matcher: Match::HeaderPresent("x-sucuri-id"),
    },
    Rule {
        product: DefenseProduct::Wordfence,
        confidence: FingerprintConfidence::Strong,
        signal: "body:generated-by-wordfence",
        matcher: Match::BodyContains("generated by wordfence"),
    },
];

/// Returns the strongest defense-product fingerprint for one response, if any.
///
/// `headers` is a transport-neutral list of `(name, value)` pairs; names are
/// matched case-insensitively. Ties at equal confidence are broken by rule
/// order, so the result is deterministic for identical inputs.
pub fn fingerprint(headers: &[(&str, &str)], body: &str) -> Option<DefenseFingerprint> {
    let body_prefix = lowercase_prefix(body, MAX_FINGERPRINT_BODY_SCAN_BYTES);

    let mut best: Option<&Rule> = None;
    for rule in RULES {
        if !rule_matches(rule, headers, &body_prefix) {
            continue;
        }
        if best.is_none_or(|current| rule.confidence > current.confidence) {
            best = Some(rule);
        }
    }

    best.map(|rule| DefenseFingerprint {
        product: rule.product,
        confidence: rule.confidence,
        signal: rule.signal,
    })
}

fn rule_matches(rule: &Rule, headers: &[(&str, &str)], body_prefix: &str) -> bool {
    match &rule.matcher {
        Match::HeaderPresent(name) => header_present(headers, name),
        Match::HeaderValueContains(name, needle) => header_value_contains(headers, name, needle),
        Match::CookieContains(needle) => cookie_contains(headers, needle),
        Match::BodyContains(needle) => body_prefix.contains(needle),
    }
}

fn header_present(headers: &[(&str, &str)], lower_name: &str) -> bool {
    headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(lower_name))
}

fn header_value_contains(headers: &[(&str, &str)], lower_name: &str, lower_needle: &str) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case(lower_name) && value.to_ascii_lowercase().contains(lower_needle)
    })
}

fn cookie_contains(headers: &[(&str, &str)], lower_needle: &str) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("set-cookie") && value.to_ascii_lowercase().contains(lower_needle)
    })
}

/// Lowercases at most `max_bytes` of `body` at a UTF-8 boundary.
fn lowercase_prefix(body: &str, max_bytes: usize) -> String {
    if body.len() <= max_bytes {
        return body.to_ascii_lowercase();
    }
    let mut end = max_bytes;
    while end > 0 && !body.is_char_boundary(end) {
        end -= 1;
    }
    body[..end].to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_headers_case_insensitively() {
        let strong = fingerprint(&[("CF-RAY", "7d1e-LHR")], "").unwrap();
        assert_eq!(strong.product(), DefenseProduct::Cloudflare);
        assert_eq!(strong.confidence(), FingerprintConfidence::Strong);

        let server = fingerprint(&[("Server", "CloudFlare")], "").unwrap();
        assert_eq!(server.product(), DefenseProduct::Cloudflare);
    }

    #[test]
    fn stronger_signal_supersedes_weaker_one() {
        // A weak Amazon request id alone is only weak.
        let weak = fingerprint(&[("x-amzn-requestid", "abc")], "").unwrap();
        assert_eq!(weak.product(), DefenseProduct::AwsWaf);
        assert_eq!(weak.confidence(), FingerprintConfidence::Weak);

        // A specific WAF action header is preferred over the weak id.
        let strong = fingerprint(
            &[("x-amzn-requestid", "abc"), ("x-amzn-waf-action", "block")],
            "",
        )
        .unwrap();
        assert_eq!(strong.confidence(), FingerprintConfidence::Probable);
    }

    #[test]
    fn amazon_s3_banner_is_not_treated_as_a_waf() {
        // The brittle legacy check inferred AWS WAF from `Server: AmazonS3`.
        // A plain S3 banner is not a WAF signal, so nothing matches.
        assert!(fingerprint(&[("Server", "AmazonS3")], "").is_none());
    }

    #[test]
    fn cookie_and_body_signals_match() {
        let f5 = fingerprint(&[("Set-Cookie", "BIGipServerpool=123; path=/")], "").unwrap();
        assert_eq!(f5.product(), DefenseProduct::F5BigIp);

        let body = fingerprint(&[], "This page is Generated by Wordfence for security").unwrap();
        assert_eq!(body.product(), DefenseProduct::Wordfence);
    }

    #[test]
    fn no_signal_returns_none() {
        assert!(fingerprint(
            &[("Server", "nginx"), ("Content-Type", "text/html")],
            "hello"
        )
        .is_none());
    }

    #[test]
    fn body_scan_is_bounded_and_deterministic() {
        let mut body = "x".repeat(MAX_FINGERPRINT_BODY_SCAN_BYTES);
        body.push_str("mod_security");
        // The needle sits past the scan ceiling, so it is not observed.
        assert!(fingerprint(&[], &body).is_none());

        let mut within = "y".repeat(64);
        within.push_str("mod_security");
        let hit = fingerprint(&[], &within).unwrap();
        assert_eq!(hit.product(), DefenseProduct::ModSecurity);
    }
}
