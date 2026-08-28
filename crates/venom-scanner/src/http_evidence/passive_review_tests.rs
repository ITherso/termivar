use reqwest::header::{HeaderMap, HeaderValue};

use super::*;

fn one_header(name: &'static str, value: impl AsRef<[u8]>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(name, HeaderValue::from_bytes(value.as_ref()).unwrap());
    headers
}

fn append_header(headers: &mut HeaderMap, name: &'static str, value: impl AsRef<[u8]>) {
    headers.append(name, HeaderValue::from_bytes(value.as_ref()).unwrap());
}

#[test]
fn missing_headers_are_explicit_and_are_not_incomplete() {
    let projection = project_passive_response(&HeaderMap::new());

    assert_eq!(
        projection.strict_transport_security().state(),
        PassiveProjectionState::Missing
    );
    assert_eq!(
        projection.content_security_policy().state(),
        PassiveProjectionState::Missing
    );
    assert_eq!(
        projection.x_content_type_options().state(),
        PassiveProjectionState::Missing
    );
    assert_eq!(
        projection.referrer_policy().state(),
        PassiveProjectionState::Missing
    );
    assert_eq!(
        projection.permissions_policy().state(),
        PassiveProjectionState::Missing
    );
    assert_eq!(
        projection.cookies().state(),
        PassiveProjectionState::Missing
    );
    assert_eq!(projection.derived_observation_count(), 6);
}

#[test]
fn parsed_projection_keeps_only_fixed_facts_and_cookie_names() {
    const COOKIE_VALUE: &str = "COOKIE_VALUE_SENTINEL";
    const CSP_NONCE: &str = "CSP_NONCE_SENTINEL";
    const CSP_HASH: &str = "CSP_HASH_SENTINEL";
    const CSP_ORIGIN: &str = "csp-origin-sentinel.test";
    const PERMISSIONS_ORIGIN: &str = "permissions-origin-sentinel.test";
    const COOKIE_DOMAIN: &str = "cookie-domain-sentinel.test";
    const COOKIE_PATH: &str = "/COOKIE_PATH_SENTINEL";

    let mut headers = HeaderMap::new();
    append_header(
        &mut headers,
        HSTS,
        "max-age=31536000; includeSubDomains; preload",
    );
    append_header(
        &mut headers,
        CSP,
        format!(
            "default-src 'self'; script-src 'nonce-{CSP_NONCE}' 'sha256-{CSP_HASH}' https://{CSP_ORIGIN}; object-src 'none'; base-uri 'none'; frame-ancestors 'self'"
        ),
    );
    append_header(&mut headers, XCTO, "nosniff");
    append_header(
        &mut headers,
        REFERRER_POLICY,
        "strict-origin-when-cross-origin",
    );
    append_header(
        &mut headers,
        PERMISSIONS_POLICY,
        format!("geolocation=(self \"https://{PERMISSIONS_ORIGIN}\"), camera=()"),
    );
    append_header(
        &mut headers,
        SET_COOKIE,
        format!(
            "session={COOKIE_VALUE}; Secure; HttpOnly; SameSite=Lax; Domain={COOKIE_DOMAIN}; Path={COOKIE_PATH}"
        ),
    );

    let projection = project_passive_response(&headers);
    let hsts = projection.strict_transport_security().metadata().unwrap();
    assert_eq!(hsts.max_age_seconds(), 31_536_000);
    assert!(hsts.includes_subdomains());
    assert!(hsts.requests_preload());
    assert!(!hsts.has_unrecognized_directive());

    let csp = projection.content_security_policy().metadata().unwrap();
    assert_eq!(csp.policy_count(), 1);
    assert_eq!(csp.directive_count(), 5);
    assert!(csp.has_default_src());
    assert!(csp.has_script_src());
    assert!(csp.has_object_src());
    assert!(csp.has_object_src_none());
    assert!(csp.has_base_uri());
    assert!(csp.has_base_uri_none());
    assert!(csp.has_frame_ancestors());
    assert!(!csp.declares_unsafe_inline());
    assert!(!csp.declares_unsafe_eval());
    assert!(csp.declares_nonce());
    assert!(csp.declares_hash());

    assert!(projection
        .x_content_type_options()
        .metadata()
        .unwrap()
        .nosniff());
    let referrer = projection.referrer_policy().metadata().unwrap();
    assert_eq!(
        referrer.effective_policy(),
        Some(ReferrerPolicyValue::StrictOriginWhenCrossOrigin)
    );
    assert_eq!(referrer.declared_policy_count(), 1);

    let permissions = projection.permissions_policy().metadata().unwrap();
    assert_eq!(permissions.directive_count(), 2);
    assert_eq!(permissions.member_count(), 2);
    assert_eq!(permissions.empty_allowlist_directives(), 1);
    assert_eq!(permissions.wildcard_members(), 0);
    assert_eq!(permissions.self_members(), 1);
    assert_eq!(permissions.src_members(), 0);
    assert_eq!(permissions.explicit_members(), 1);
    assert!(!permissions.duplicate_feature_directives());

    let cookies = projection.cookies().metadata().unwrap();
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name(), "session");
    assert!(cookies[0].secure());
    assert!(cookies[0].http_only());
    assert_eq!(cookies[0].same_site(), PassiveCookieSameSite::Lax);
    assert!(cookies[0].domain_attribute_present());
    assert!(cookies[0].path_attribute_present());

    let debug = format!("{projection:?}");
    for sentinel in [
        COOKIE_VALUE,
        CSP_NONCE,
        CSP_HASH,
        CSP_ORIGIN,
        PERMISSIONS_ORIGIN,
        COOKIE_DOMAIN,
        COOKIE_PATH,
    ] {
        assert!(!debug.contains(sentinel), "projection leaked {sentinel}");
    }
}

#[test]
fn debug_projection_redacts_user_controlled_cookie_names() {
    let headers = one_header(
        "set-cookie",
        "DEBUG_COOKIE_NAME_SENTINEL=value; Secure; SameSite=Lax",
    );
    let projection = project_passive_response(&headers);
    assert_eq!(
        projection.cookies().metadata().unwrap()[0].name(),
        "DEBUG_COOKIE_NAME_SENTINEL"
    );
    let debug = format!(
        "{projection:?}{:?}",
        projection.cookies().metadata().unwrap()[0]
    );
    assert!(!debug.contains("DEBUG_COOKIE_NAME_SENTINEL"));
    assert!(debug.contains("cookie_count"));
    assert!(debug.contains("<redacted>"));
}

#[test]
fn syntactically_readable_but_nonconformant_values_are_not_parsed_success() {
    let cases = [
        (HSTS, "includeSubDomains"),
        (CSP, "default-src 'self'; default-src 'none'"),
        (XCTO, "sniff"),
        (REFERRER_POLICY, "future-policy"),
        (PERMISSIONS_POLICY, "camera=(), camera=(self)"),
        (SET_COOKIE, "session=value; SameSite=None"),
    ];

    for (name, value) in cases {
        let projection = project_passive_response(&one_header(name, value));
        let state = match name {
            HSTS => projection.strict_transport_security().state(),
            CSP => projection.content_security_policy().state(),
            XCTO => projection.x_content_type_options().state(),
            REFERRER_POLICY => projection.referrer_policy().state(),
            PERMISSIONS_POLICY => projection.permissions_policy().state(),
            SET_COOKIE => projection.cookies().state(),
            _ => unreachable!(),
        };
        assert_eq!(state, PassiveProjectionState::Nonconformant, "{name}");
    }
}

#[test]
fn malformed_values_are_distinct_from_missing_and_incomplete() {
    let cases = [
        (HSTS, "max-age=not-a-number"),
        (CSP, ","),
        (XCTO, "not valid"),
        (REFERRER_POLICY, ","),
        (PERMISSIONS_POLICY, "camera=(self"),
        (SET_COOKIE, "missing-cookie-pair"),
    ];

    for (name, value) in cases {
        let projection = project_passive_response(&one_header(name, value));
        let state = match name {
            HSTS => projection.strict_transport_security().state(),
            CSP => projection.content_security_policy().state(),
            XCTO => projection.x_content_type_options().state(),
            REFERRER_POLICY => projection.referrer_policy().state(),
            PERMISSIONS_POLICY => projection.permissions_policy().state(),
            SET_COOKIE => projection.cookies().state(),
            _ => unreachable!(),
        };
        assert_eq!(state, PassiveProjectionState::Malformed, "{name}");
    }
}

#[test]
fn header_occurrence_and_value_byte_limits_accept_the_exact_boundary() {
    let mut at_occurrence_limit = HeaderMap::new();
    for _ in 0..MAX_PASSIVE_HEADER_OCCURRENCES {
        append_header(&mut at_occurrence_limit, HSTS, "max-age=1");
    }
    assert_ne!(
        project_passive_response(&at_occurrence_limit)
            .strict_transport_security()
            .state(),
        PassiveProjectionState::ProjectionIncomplete
    );
    append_header(&mut at_occurrence_limit, HSTS, "max-age=1");
    let projected = project_passive_response(&at_occurrence_limit);
    assert_eq!(
        projected.strict_transport_security().state(),
        PassiveProjectionState::ProjectionIncomplete
    );
    assert_eq!(
        projected.strict_transport_security().incomplete_reason(),
        Some(PassiveProjectionIncompleteReason::TooManyHeaderOccurrences)
    );

    let at_value_limit = "a".repeat(MAX_PASSIVE_HEADER_VALUE_BYTES);
    assert_ne!(
        project_passive_response(&one_header(XCTO, &at_value_limit))
            .x_content_type_options()
            .state(),
        PassiveProjectionState::ProjectionIncomplete
    );
    let above_value_limit = "a".repeat(MAX_PASSIVE_HEADER_VALUE_BYTES + 1);
    let projected = project_passive_response(&one_header(XCTO, &above_value_limit));
    assert_eq!(
        projected.x_content_type_options().state(),
        PassiveProjectionState::ProjectionIncomplete
    );
    assert_eq!(
        projected.x_content_type_options().incomplete_reason(),
        Some(PassiveProjectionIncompleteReason::OversizedHeaderValue)
    );
}

#[test]
fn csp_policy_and_directive_limits_accept_the_exact_boundary() {
    let policies = std::iter::repeat_n("default-src 'self'", MAX_PASSIVE_CSP_POLICIES)
        .collect::<Vec<_>>()
        .join(",");
    let projected = project_passive_response(&one_header(CSP, &policies));
    assert_eq!(
        projected.content_security_policy().state(),
        PassiveProjectionState::Parsed
    );
    assert_eq!(
        usize::from(
            projected
                .content_security_policy()
                .metadata()
                .unwrap()
                .policy_count()
        ),
        MAX_PASSIVE_CSP_POLICIES
    );
    let too_many_policies = format!("{policies},default-src 'self'");
    let projected = project_passive_response(&one_header(CSP, too_many_policies));
    assert_eq!(
        projected.content_security_policy().incomplete_reason(),
        Some(PassiveProjectionIncompleteReason::TooManyCspPolicies)
    );

    let directives = (0..MAX_PASSIVE_CSP_DIRECTIVES)
        .map(|index| format!("x-{index} 'self'"))
        .collect::<Vec<_>>()
        .join(";");
    let projected = project_passive_response(&one_header(CSP, &directives));
    assert_eq!(
        usize::from(
            projected
                .content_security_policy()
                .metadata()
                .unwrap()
                .directive_count()
        ),
        MAX_PASSIVE_CSP_DIRECTIVES
    );
    let too_many_directives = format!("{directives};x-overflow 'self'");
    let projected = project_passive_response(&one_header(CSP, too_many_directives));
    assert_eq!(
        projected.content_security_policy().incomplete_reason(),
        Some(PassiveProjectionIncompleteReason::TooManyCspDirectives)
    );
}

#[test]
fn permissions_policy_limits_accept_exact_directive_and_member_boundaries() {
    let directives = (0..MAX_PASSIVE_PERMISSIONS_POLICY_DIRECTIVES)
        .map(|index| format!("feature-{index}=()"))
        .collect::<Vec<_>>()
        .join(",");
    let projected = project_passive_response(&one_header(PERMISSIONS_POLICY, &directives));
    assert_eq!(
        usize::from(
            projected
                .permissions_policy()
                .metadata()
                .unwrap()
                .directive_count()
        ),
        MAX_PASSIVE_PERMISSIONS_POLICY_DIRECTIVES
    );
    let too_many_directives = format!("{directives},overflow=()");
    let projected = project_passive_response(&one_header(PERMISSIONS_POLICY, too_many_directives));
    assert_eq!(
        projected.permissions_policy().incomplete_reason(),
        Some(PassiveProjectionIncompleteReason::TooManyPermissionsPolicyDirectives)
    );

    let members = std::iter::repeat_n("self", MAX_PASSIVE_PERMISSIONS_POLICY_MEMBERS)
        .collect::<Vec<_>>()
        .join(" ");
    let projected = project_passive_response(&one_header(
        PERMISSIONS_POLICY,
        format!("camera=({members})"),
    ));
    assert_eq!(
        usize::from(
            projected
                .permissions_policy()
                .metadata()
                .unwrap()
                .member_count()
        ),
        MAX_PASSIVE_PERMISSIONS_POLICY_MEMBERS
    );
    let projected = project_passive_response(&one_header(
        PERMISSIONS_POLICY,
        format!("camera=({members} self)"),
    ));
    assert_eq!(
        projected.permissions_policy().incomplete_reason(),
        Some(PassiveProjectionIncompleteReason::TooManyPermissionsPolicyMembers)
    );
}

#[test]
fn set_cookie_occurrence_pair_name_and_attribute_limits_are_exact() {
    let mut headers = HeaderMap::new();
    for index in 0..MAX_PASSIVE_SET_COOKIE_OCCURRENCES {
        append_header(&mut headers, SET_COOKIE, format!("cookie{index}=value"));
    }
    let projected = project_passive_response(&headers);
    assert_eq!(
        projected.cookies().metadata().unwrap().len(),
        MAX_PASSIVE_SET_COOKIE_OCCURRENCES
    );
    append_header(&mut headers, SET_COOKIE, "overflow=value");
    let projected = project_passive_response(&headers);
    assert_eq!(
        projected.cookies().incomplete_reason(),
        Some(PassiveProjectionIncompleteReason::TooManySetCookieOccurrences)
    );

    let cookie_prefix = "n=v; extension=";
    let value_at_limit = format!(
        "{cookie_prefix}{}",
        "a".repeat(MAX_PASSIVE_SET_COOKIE_VALUE_BYTES - cookie_prefix.len())
    );
    assert_eq!(value_at_limit.len(), MAX_PASSIVE_SET_COOKIE_VALUE_BYTES);
    assert_ne!(
        project_passive_response(&one_header(SET_COOKIE, &value_at_limit))
            .cookies()
            .state(),
        PassiveProjectionState::ProjectionIncomplete
    );
    let value_above_limit = format!("{value_at_limit}a");
    assert_eq!(
        project_passive_response(&one_header(SET_COOKIE, value_above_limit))
            .cookies()
            .incomplete_reason(),
        Some(PassiveProjectionIncompleteReason::OversizedSetCookieValue)
    );

    let pair_at_limit = format!("n={}", "a".repeat(MAX_PASSIVE_COOKIE_PAIR_BYTES - 2));
    assert_eq!(pair_at_limit.len(), MAX_PASSIVE_COOKIE_PAIR_BYTES);
    assert_eq!(
        project_passive_response(&one_header(SET_COOKIE, &pair_at_limit))
            .cookies()
            .state(),
        PassiveProjectionState::Parsed
    );
    let pair_above_limit = format!("{pair_at_limit}a");
    assert_eq!(
        project_passive_response(&one_header(SET_COOKIE, pair_above_limit))
            .cookies()
            .incomplete_reason(),
        Some(PassiveProjectionIncompleteReason::OversizedCookiePair)
    );

    let name_at_limit = "n".repeat(MAX_PASSIVE_COOKIE_NAME_BYTES);
    assert_eq!(
        project_passive_response(&one_header(SET_COOKIE, format!("{name_at_limit}=value")))
            .cookies()
            .state(),
        PassiveProjectionState::Parsed
    );
    let name_above_limit = format!("{name_at_limit}n");
    assert_eq!(
        project_passive_response(&one_header(SET_COOKIE, format!("{name_above_limit}=value")))
            .cookies()
            .incomplete_reason(),
        Some(PassiveProjectionIncompleteReason::OversizedCookieName)
    );

    let attributes = (0..MAX_PASSIVE_COOKIE_ATTRIBUTES)
        .map(|index| format!("attribute-{index}=value"))
        .collect::<Vec<_>>()
        .join("; ");
    assert_eq!(
        project_passive_response(&one_header(
            SET_COOKIE,
            format!("session=value; {attributes}")
        ))
        .cookies()
        .state(),
        PassiveProjectionState::Parsed
    );
    let too_many_attributes = format!("session=value; {attributes}; overflow=value");
    assert_eq!(
        project_passive_response(&one_header(SET_COOKIE, too_many_attributes))
            .cookies()
            .incomplete_reason(),
        Some(PassiveProjectionIncompleteReason::TooManyCookieAttributes)
    );
}

#[test]
fn cookie_domain_and_path_inspection_limits_accept_the_exact_boundary() {
    let domain = "d".repeat(MAX_PASSIVE_COOKIE_SCOPE_VALUE_BYTES);
    let path = format!("/{}", "p".repeat(MAX_PASSIVE_COOKIE_SCOPE_VALUE_BYTES - 1));
    let projected = project_passive_response(&one_header(
        SET_COOKIE,
        format!("session=value; Domain={domain}; Path={path}"),
    ));
    assert_ne!(
        projected.cookies().state(),
        PassiveProjectionState::ProjectionIncomplete
    );

    let domain = format!("{domain}d");
    let projected = project_passive_response(&one_header(
        SET_COOKIE,
        format!("session=value; Domain={domain}"),
    ));
    assert_eq!(
        projected.cookies().incomplete_reason(),
        Some(PassiveProjectionIncompleteReason::OversizedCookieScopeValue)
    );

    let path = format!(
        "/{:p>width$}",
        "",
        width = MAX_PASSIVE_COOKIE_SCOPE_VALUE_BYTES
    );
    let projected = project_passive_response(&one_header(
        SET_COOKIE,
        format!("session=value; Path={path}"),
    ));
    assert_eq!(
        projected.cookies().incomplete_reason(),
        Some(PassiveProjectionIncompleteReason::OversizedCookieScopeValue)
    );
}

#[test]
fn derived_observation_limit_accepts_the_exact_boundary() {
    assert_eq!(
        enforce_derived_observation_limit(MAX_PASSIVE_DERIVED_OBSERVATIONS),
        Ok(u16::try_from(MAX_PASSIVE_DERIVED_OBSERVATIONS).unwrap())
    );
    assert_eq!(
        enforce_derived_observation_limit(MAX_PASSIVE_DERIVED_OBSERVATIONS + 1),
        Err(PassiveProjectionIncompleteReason::TooManyDerivedObservations)
    );
}
