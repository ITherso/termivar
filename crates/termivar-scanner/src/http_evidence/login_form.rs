//! Private, bounded extraction of one policy-bound form-login CSRF value.

use std::{borrow::Cow, cell::Cell, fmt};

use html5ever::{
    ns, parse_document,
    tendril::{StrTendril, TendrilSink},
    tree_builder::{ElementFlags, NodeOrText, QuirksMode, TreeSink},
    Attribute, ExpandedName, LocalName, Namespace, ParseOpts, QualName,
};
use markup5ever_rcdom::{Handle, NodeData, RcDom};
use thiserror::Error;
use zeroize::Zeroizing;

use super::{normalized_media_type, CollectedHttpResponse};
use crate::supplied_session_review::SuppliedSessionPolicy;

const MAX_LOGIN_FORM_HTML_BYTES: usize = 64 * 1024;
const MAX_LOGIN_FORM_DOM_NODES: usize = 2_048;
const LOGIN_FORM_PARSE_CHUNK_BYTES: usize = 256;
const MAX_LOGIN_CSRF_VALUE_BYTES: usize = 2 * 1024;
const FORM_URLENCODED: &str = "application/x-www-form-urlencoded";
const DUPLICATE_ATTRIBUTE_MARKER_NAMESPACE: &str = "urn:termivar:internal:login-form";
const DUPLICATE_ATTRIBUTE_MARKER_LOCAL_NAME: &str = "had-duplicate-attributes";

/// `RcDom` adapter that caps the accepted, attached representation while
/// preserving every tree-builder handle-identity invariant.
///
/// `TreeSink` has no abort result. Once the cap is crossed, node-producing
/// callbacks therefore return fresh detached `RcDom` handles while mutation
/// callbacks become no-ops. Reusing one overflow sentinel is unsound because
/// the tree builder records handle identity in its open-element and active-
/// formatting stacks. The outer decoder checks the flag after each 256-byte
/// input chunk and once after bounded EOF finalization. Consequently the
/// accepted DOM never exceeds this cap; transient detached handles are bounded
/// by one input chunk (or EOF work over the already bounded parser state) and
/// the pre-existing 64-KiB document ceiling. This is not a claim that peak
/// allocations can never exceed the accepted-node count.
struct BoundedLoginFormDom {
    inner: RcDom,
    retained_nodes: Cell<usize>,
    limit_exceeded: Cell<bool>,
}

impl BoundedLoginFormDom {
    fn new() -> Self {
        Self {
            inner: RcDom::default(),
            retained_nodes: Cell::new(1),
            limit_exceeded: Cell::new(false),
        }
    }

    fn reserve_nodes(&self, count: usize) -> bool {
        if self.limit_exceeded.get() {
            return false;
        }
        let Some(next) = self.retained_nodes.get().checked_add(count) else {
            self.limit_exceeded.set(true);
            return false;
        };
        if next > MAX_LOGIN_FORM_DOM_NODES {
            self.limit_exceeded.set(true);
            return false;
        }
        self.retained_nodes.set(next);
        true
    }

    fn limit_exceeded(&self) -> bool {
        self.limit_exceeded.get()
    }

    fn into_inner(self) -> RcDom {
        self.inner
    }

    #[cfg(test)]
    fn retained_node_count(&self) -> usize {
        self.retained_nodes.get()
    }
}

impl TreeSink for BoundedLoginFormDom {
    type Handle = Handle;
    type Output = Self;
    type ElemName<'a>
        = ExpandedName<'a>
    where
        Self: 'a;

    fn finish(self) -> Self::Output {
        self
    }

    fn parse_error(&self, message: Cow<'static, str>) {
        if self.reserve_nodes(1) {
            self.inner.parse_error(message);
        }
    }

    fn get_document(&self) -> Self::Handle {
        self.inner.get_document()
    }

    fn elem_name<'a>(&'a self, target: &'a Self::Handle) -> Self::ElemName<'a> {
        self.inner.elem_name(target)
    }

    fn create_element(
        &self,
        name: QualName,
        mut attrs: Vec<Attribute>,
        flags: ElementFlags,
    ) -> Self::Handle {
        let retained_nodes = if flags.template { 2 } else { 1 };
        let _ = self.reserve_nodes(retained_nodes);
        // html5ever removes duplicate attributes before the tree sink sees the
        // retained attribute vector, but preserves that fact in `ElementFlags`.
        // Carry it on the private DOM node so validation can reject duplicates
        // only on the selected form and its policy-relevant controls. A private
        // namespace prevents untrusted HTML from manufacturing this marker.
        if flags.had_duplicate_attributes {
            attrs.push(Attribute {
                name: QualName::new(
                    None,
                    Namespace::from(DUPLICATE_ATTRIBUTE_MARKER_NAMESPACE),
                    LocalName::from(DUPLICATE_ATTRIBUTE_MARKER_LOCAL_NAME),
                ),
                value: StrTendril::new(),
            });
        }
        // Always return a fresh handle. If reservation failed, the flag is set
        // and the following append callback leaves the node detached.
        self.inner.create_element(name, attrs, flags)
    }

    fn create_comment(&self, text: StrTendril) -> Self::Handle {
        let _ = self.reserve_nodes(1);
        self.inner.create_comment(text)
    }

    fn create_pi(&self, target: StrTendril, data: StrTendril) -> Self::Handle {
        let _ = self.reserve_nodes(1);
        self.inner.create_pi(target, data)
    }

    fn append(&self, parent: &Self::Handle, child: NodeOrText<Self::Handle>) {
        if self.limit_exceeded() {
            return;
        }
        let creates_text_node = matches!(&child, NodeOrText::AppendText(_))
            && !parent
                .children
                .borrow()
                .last()
                .is_some_and(|node| matches!(&node.data, NodeData::Text { .. }));
        if creates_text_node && !self.reserve_nodes(1) {
            return;
        }
        self.inner.append(parent, child);
    }

    fn append_based_on_parent_node(
        &self,
        element: &Self::Handle,
        previous_element: &Self::Handle,
        child: NodeOrText<Self::Handle>,
    ) {
        if self.limit_exceeded() {
            return;
        }
        if matches!(&child, NodeOrText::AppendText(_)) && !self.reserve_nodes(1) {
            return;
        }
        self.inner
            .append_based_on_parent_node(element, previous_element, child);
    }

    fn append_doctype_to_document(
        &self,
        name: StrTendril,
        public_id: StrTendril,
        system_id: StrTendril,
    ) {
        if self.reserve_nodes(1) {
            self.inner
                .append_doctype_to_document(name, public_id, system_id);
        }
    }

    fn get_template_contents(&self, target: &Self::Handle) -> Self::Handle {
        self.inner.get_template_contents(target)
    }

    fn same_node(&self, left: &Self::Handle, right: &Self::Handle) -> bool {
        self.inner.same_node(left, right)
    }

    fn set_quirks_mode(&self, mode: QuirksMode) {
        self.inner.set_quirks_mode(mode);
    }

    fn append_before_sibling(&self, sibling: &Self::Handle, new_node: NodeOrText<Self::Handle>) {
        if self.limit_exceeded() {
            return;
        }
        if matches!(&new_node, NodeOrText::AppendText(_)) && !self.reserve_nodes(1) {
            return;
        }
        self.inner.append_before_sibling(sibling, new_node);
    }

    fn add_attrs_if_missing(&self, target: &Self::Handle, attrs: Vec<Attribute>) {
        if !self.limit_exceeded() {
            self.inner.add_attrs_if_missing(target, attrs);
        }
    }

    fn remove_from_parent(&self, target: &Self::Handle) {
        if !self.limit_exceeded() {
            self.inner.remove_from_parent(target);
        }
    }

    fn reparent_children(&self, node: &Self::Handle, new_parent: &Self::Handle) {
        if !self.limit_exceeded() {
            self.inner.reparent_children(node, new_parent);
        }
    }

    fn is_mathml_annotation_xml_integration_point(&self, target: &Self::Handle) -> bool {
        self.inner
            .is_mathml_annotation_xml_integration_point(target)
    }
}

/// Static, value-free reason that a login document could not authorize a POST.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum SuppliedSessionLoginFormError {
    /// The response was not the exact complete successful HTML representation.
    #[error("supplied-session login response is ineligible")]
    IneligibleResponse,
    /// No form targeted the exact configured login path (or the current document).
    #[error("supplied-session login form is missing")]
    MissingForm,
    /// More than one form targeted the exact configured login path.
    #[error("supplied-session login form is ambiguous")]
    AmbiguousForm,
    /// The selected form did not have the exact bounded POST/control contract.
    #[error("supplied-session login form contract is invalid")]
    InvalidFormContract,
    /// The selected form did not contain the configured CSRF control.
    #[error("supplied-session login CSRF control is missing")]
    MissingCsrf,
    /// The selected form contained more than one configured CSRF control.
    #[error("supplied-session login CSRF control is ambiguous")]
    AmbiguousCsrf,
    /// The selected CSRF control type or guarded value was invalid.
    #[error("supplied-session login CSRF value is invalid")]
    InvalidCsrf,
}

impl SuppliedSessionLoginFormError {
    /// Stable value-free audit code. No response or form content is included.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::IneligibleResponse => "ineligible_response",
            Self::MissingForm => "missing_form",
            Self::AmbiguousForm => "ambiguous_form",
            Self::InvalidFormContract => "invalid_form_contract",
            Self::MissingCsrf => "missing_csrf",
            Self::AmbiguousCsrf => "ambiguous_csrf",
            Self::InvalidCsrf => "invalid_csrf",
        }
    }
}

/// Move-only guarded CSRF value from one eligible login representation.
///
/// The raw value has no serialization implementation and its `Debug` output is
/// always redacted. It is exposed only long enough for the policy-bound form
/// body composer to percent-encode the single login attempt.
pub(crate) struct SuppliedSessionLoginCsrfToken {
    value: Zeroizing<String>,
}

impl SuppliedSessionLoginCsrfToken {
    pub(crate) fn as_str(&self) -> &str {
        self.value.as_str()
    }
}

impl fmt::Debug for SuppliedSessionLoginCsrfToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SuppliedSessionLoginCsrfToken(<redacted>)")
    }
}

/// Extracts one exact hidden CSRF value from the policy-selected login form.
///
/// This function is deliberately not an evidence producer. It accepts only a
/// complete status-200 UTF-8 `text/html` body whose final URL is exactly the
/// policy login URL. The document, form set, controls, and returned secret are
/// all bounded before they can authorize the single form POST.
pub(crate) fn extract_supplied_session_login_csrf(
    response: &CollectedHttpResponse,
    policy: &SuppliedSessionPolicy,
) -> Result<SuppliedSessionLoginCsrfToken, SuppliedSessionLoginFormError> {
    let Some(login_url) = policy.login_url() else {
        return Err(SuppliedSessionLoginFormError::IneligibleResponse);
    };
    if response.status() != 200
        || !response.body_complete()
        || response.final_url() != login_url
        || normalized_media_type(&response.headers).as_deref() != Some("text/html")
        || response.body().len() > MAX_LOGIN_FORM_HTML_BYTES
        || response.body().len() > policy.max_response_body_bytes()
    {
        return Err(SuppliedSessionLoginFormError::IneligibleResponse);
    }
    let document = std::str::from_utf8(response.body())
        .map_err(|_| SuppliedSessionLoginFormError::IneligibleResponse)?;
    let (Some(username_field), Some(password_field), Some(csrf_field)) = (
        policy.login_username_field(),
        policy.login_password_field(),
        policy.login_csrf_field(),
    ) else {
        return Err(SuppliedSessionLoginFormError::IneligibleResponse);
    };

    let dom = parse_bounded_login_form_dom(document)?;
    let forms = selected_forms(&dom.document, login_url.path())?;
    let form = match forms.as_slice() {
        [] => return Err(SuppliedSessionLoginFormError::MissingForm),
        [form] => form,
        _ => return Err(SuppliedSessionLoginFormError::AmbiguousForm),
    };
    validate_form_contract(form)?;
    let value = extract_controls(form, username_field, password_field, csrf_field)?;
    Ok(SuppliedSessionLoginCsrfToken {
        value: Zeroizing::new(value),
    })
}

fn parse_bounded_login_form_dom(document: &str) -> Result<RcDom, SuppliedSessionLoginFormError> {
    let mut parser = parse_document(BoundedLoginFormDom::new(), ParseOpts::default());
    let mut start = 0_usize;
    while start < document.len() {
        let mut end = start
            .saturating_add(LOGIN_FORM_PARSE_CHUNK_BYTES)
            .min(document.len());
        while end > start && !document.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            return Err(SuppliedSessionLoginFormError::InvalidFormContract);
        }
        parser.process(StrTendril::from_slice(&document[start..end]));
        if parser.tokenizer.sink.sink.limit_exceeded() {
            return Err(SuppliedSessionLoginFormError::InvalidFormContract);
        }
        start = end;
    }
    let bounded = parser.finish();
    if bounded.limit_exceeded() {
        return Err(SuppliedSessionLoginFormError::InvalidFormContract);
    }
    Ok(bounded.into_inner())
}

fn selected_forms(
    document: &Handle,
    exact_login_path: &str,
) -> Result<Vec<Handle>, SuppliedSessionLoginFormError> {
    let mut pending = vec![document.clone()];
    let mut visited = 0_usize;
    let mut forms = Vec::new();
    while let Some(handle) = pending.pop() {
        visited = visited.saturating_add(1);
        if visited > MAX_LOGIN_FORM_DOM_NODES {
            return Err(SuppliedSessionLoginFormError::InvalidFormContract);
        }
        if let NodeData::Element { name, attrs, .. } = &handle.data {
            if name.ns == ns!(html) && name.local.as_ref() == "form" {
                let attrs = attrs.borrow();
                let action = unqualified_attribute(&attrs, "action");
                if action.is_none() || action == Some(exact_login_path) {
                    forms.push(handle.clone());
                }
            }
        }
        pending.extend(handle.children.borrow().iter().cloned());
    }
    Ok(forms)
}

fn validate_form_contract(form: &Handle) -> Result<(), SuppliedSessionLoginFormError> {
    let NodeData::Element { attrs, .. } = &form.data else {
        return Err(SuppliedSessionLoginFormError::InvalidFormContract);
    };
    let attrs = attrs.borrow();
    if had_duplicate_attributes(&attrs) {
        return Err(SuppliedSessionLoginFormError::InvalidFormContract);
    }
    let method = unqualified_attribute(&attrs, "method");
    let encoding = unqualified_attribute(&attrs, "enctype");
    if !method.is_some_and(|value| value.eq_ignore_ascii_case("post"))
        || encoding.is_some_and(|value| !value.eq_ignore_ascii_case(FORM_URLENCODED))
    {
        return Err(SuppliedSessionLoginFormError::InvalidFormContract);
    }
    Ok(())
}

fn extract_controls(
    form: &Handle,
    username_field: &str,
    password_field: &str,
    csrf_field: &str,
) -> Result<String, SuppliedSessionLoginFormError> {
    let mut pending = form
        .children
        .borrow()
        .iter()
        .cloned()
        .map(|handle| (handle, false))
        .collect::<Vec<_>>();
    let mut username_count = 0_usize;
    let mut password_count = 0_usize;
    let mut csrf_count = 0_usize;
    let mut csrf_value = None;

    while let Some((handle, disabled_by_fieldset)) = pending.pop() {
        let mut descendants_disabled = disabled_by_fieldset;
        if let NodeData::Element { name, attrs, .. } = &handle.data {
            if name.ns == ns!(html) && name.local.as_ref() == "form" {
                return Err(SuppliedSessionLoginFormError::InvalidFormContract);
            }
            if name.ns == ns!(html) && name.local.as_ref() == "fieldset" {
                let attrs = attrs.borrow();
                if unqualified_attribute(&attrs, "disabled").is_some() {
                    descendants_disabled = true;
                }
            }
            if name.ns == ns!(html)
                && matches!(
                    name.local.as_ref(),
                    "input" | "select" | "textarea" | "button"
                )
            {
                let attrs = attrs.borrow();
                let Some(control_name) = unqualified_attribute(&attrs, "name") else {
                    pending.extend(
                        handle
                            .children
                            .borrow()
                            .iter()
                            .cloned()
                            .map(|child| (child, descendants_disabled)),
                    );
                    continue;
                };
                let disabled =
                    disabled_by_fieldset || unqualified_attribute(&attrs, "disabled").is_some();
                let reassociated = unqualified_attribute(&attrs, "form").is_some();
                let control_type = unqualified_attribute(&attrs, "type");
                if control_name == username_field {
                    username_count = username_count.saturating_add(1);
                    if had_duplicate_attributes(&attrs)
                        || name.local.as_ref() != "input"
                        || disabled
                        || reassociated
                        || control_type.is_some_and(|value| !value.eq_ignore_ascii_case("text"))
                    {
                        return Err(SuppliedSessionLoginFormError::InvalidFormContract);
                    }
                } else if control_name == password_field {
                    password_count = password_count.saturating_add(1);
                    if had_duplicate_attributes(&attrs)
                        || name.local.as_ref() != "input"
                        || disabled
                        || reassociated
                        || !control_type.is_some_and(|value| value.eq_ignore_ascii_case("password"))
                    {
                        return Err(SuppliedSessionLoginFormError::InvalidFormContract);
                    }
                } else if control_name == csrf_field {
                    csrf_count = csrf_count.saturating_add(1);
                    if had_duplicate_attributes(&attrs)
                        || name.local.as_ref() != "input"
                        || disabled
                        || reassociated
                        || !control_type.is_some_and(|value| value.eq_ignore_ascii_case("hidden"))
                    {
                        return Err(SuppliedSessionLoginFormError::InvalidCsrf);
                    }
                    let Some(value) = unqualified_attribute(&attrs, "value") else {
                        return Err(SuppliedSessionLoginFormError::InvalidCsrf);
                    };
                    if !valid_csrf_value(value) {
                        return Err(SuppliedSessionLoginFormError::InvalidCsrf);
                    }
                    csrf_value = Some(value.to_owned());
                }
            }
        }
        pending.extend(
            handle
                .children
                .borrow()
                .iter()
                .cloned()
                .map(|child| (child, descendants_disabled)),
        );
    }

    if username_count != 1 || password_count != 1 {
        return Err(SuppliedSessionLoginFormError::InvalidFormContract);
    }
    match csrf_count {
        0 => Err(SuppliedSessionLoginFormError::MissingCsrf),
        1 => csrf_value.ok_or(SuppliedSessionLoginFormError::InvalidCsrf),
        _ => Err(SuppliedSessionLoginFormError::AmbiguousCsrf),
    }
}

fn unqualified_attribute<'a>(
    attrs: &'a [html5ever::Attribute],
    local_name: &str,
) -> Option<&'a str> {
    attrs
        .iter()
        .find(|attribute| attribute.name.ns == ns!() && attribute.name.local.as_ref() == local_name)
        .map(|attribute| attribute.value.as_ref())
}

fn had_duplicate_attributes(attrs: &[html5ever::Attribute]) -> bool {
    attrs.iter().any(|attribute| {
        attribute.name.ns.as_ref() == DUPLICATE_ATTRIBUTE_MARKER_NAMESPACE
            && attribute.name.local.as_ref() == DUPLICATE_ATTRIBUTE_MARKER_LOCAL_NAME
    })
}

fn valid_csrf_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LOGIN_CSRF_VALUE_BYTES
        && !value
            .chars()
            .any(|character| matches!(character, '\0' | '\r' | '\n' | '\u{fffd}'))
}

#[cfg(test)]
mod tests {
    use html5ever::local_name;
    use reqwest::{header::HeaderMap, StatusCode, Url};

    use super::*;
    use crate::supplied_session_review::{
        SuppliedSessionPolicy, SUPPLIED_SESSION_FORM_LOGIN_POLICY_SCHEMA,
    };

    const LOGIN_URL: &str = "https://example.test/app/login";
    const VALID_FORM: &str = "<form action=\"/app/login\" method=\"POST\"><input name=\"user\"><input type=\"password\" name=\"pass\"><input value=\"TOKEN-CANARY\" name=\"csrf\" type=\"hidden\"></form>";

    fn policy() -> SuppliedSessionPolicy {
        let application = Url::parse("https://example.test/app/").unwrap();
        let source = format!(
            r#"schema = "{SUPPLIED_SESSION_FORM_LOGIN_POLICY_SCHEMA}"
principal_alias = "fixture-user"
credential_mechanism = "cookie_jar"
credential_acquisition = "bounded_form_login"
cookie_update_policy = "stop_on_selected_cookie"
login_path = "/app/login"
login_method = "post"
login_encoding = "application/x-www-form-urlencoded"
username_field = "user"
password_field = "pass"
csrf_field = "csrf"
max_login_attempts = 1
health_path = "/app/health"
health_json_field = "authenticated"
resources = ["/app/private"]
max_session_requests = 5
max_total_response_bytes = 262144
max_response_body_bytes = 65536
max_wall_time_ms = 10000

[[cookies]]
id = "session-cookie"
name = "session"
domain = "example.test"
host_only = true
path = "/app/"
secure = true
http_only = true
same_site = "lax"
"#
        );
        SuppliedSessionPolicy::parse_toml(&application, source.as_bytes()).unwrap()
    }

    fn response(body: impl Into<Vec<u8>>) -> CollectedHttpResponse {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", "text/html; charset=utf-8".parse().unwrap());
        CollectedHttpResponse {
            status: StatusCode::OK,
            final_url: Url::parse(LOGIN_URL).unwrap(),
            version: "HTTP/1.1".to_owned(),
            headers,
            body: body.into(),
            body_truncated: false,
            body_complete: true,
            ttfb_ms: 1,
            total_ms: 2,
        }
    }

    fn extract(body: &str) -> Result<SuppliedSessionLoginCsrfToken, SuppliedSessionLoginFormError> {
        extract_supplied_session_login_csrf(&response(body.as_bytes()), &policy())
    }

    fn extraction_error(body: &str) -> SuppliedSessionLoginFormError {
        extract(body).expect_err("fixture must be rejected")
    }

    #[test]
    fn extracts_one_guarded_value_from_the_exact_form() {
        let token = extract(VALID_FORM).unwrap();
        assert!(token.as_str() == "TOKEN-CANARY");
        assert_eq!(
            format!("{token:?}"),
            "SuppliedSessionLoginCsrfToken(<redacted>)"
        );
        assert!(!format!("{token:?}").contains("TOKEN-CANARY"));

        let self_action = VALID_FORM.replace(" action=\"/app/login\"", "");
        assert!(extract(&self_action).is_ok());
        let encoding = VALID_FORM.replace(
            "method=\"POST\"",
            "method=\"POST\" enctype=\"APPLICATION/X-WWW-FORM-URLENCODED\"",
        );
        assert!(extract(&encoding).is_ok());
        assert_eq!(
            SuppliedSessionLoginFormError::AmbiguousCsrf.as_str(),
            "ambiguous_csrf"
        );
    }

    #[test]
    fn rejects_ineligible_response_boundaries() {
        let selected_policy = policy();

        let mut wrong_status = response(VALID_FORM.as_bytes());
        wrong_status.status = StatusCode::CREATED;
        assert_eq!(
            extract_supplied_session_login_csrf(&wrong_status, &selected_policy).unwrap_err(),
            SuppliedSessionLoginFormError::IneligibleResponse
        );

        let mut wrong_url = response(VALID_FORM.as_bytes());
        wrong_url.final_url = Url::parse("https://example.test/app/other").unwrap();
        assert_eq!(
            extract_supplied_session_login_csrf(&wrong_url, &selected_policy).unwrap_err(),
            SuppliedSessionLoginFormError::IneligibleResponse
        );

        let mut incomplete = response(VALID_FORM.as_bytes());
        incomplete.body_complete = false;
        assert_eq!(
            extract_supplied_session_login_csrf(&incomplete, &selected_policy).unwrap_err(),
            SuppliedSessionLoginFormError::IneligibleResponse
        );

        let mut truncated = response(VALID_FORM.as_bytes());
        truncated.body_truncated = true;
        assert_eq!(
            extract_supplied_session_login_csrf(&truncated, &selected_policy).unwrap_err(),
            SuppliedSessionLoginFormError::IneligibleResponse
        );

        let mut wrong_media = response(VALID_FORM.as_bytes());
        wrong_media
            .headers
            .insert("content-type", "text/plain".parse().unwrap());
        assert_eq!(
            extract_supplied_session_login_csrf(&wrong_media, &selected_policy).unwrap_err(),
            SuppliedSessionLoginFormError::IneligibleResponse
        );

        assert_eq!(
            extract_supplied_session_login_csrf(&response([0xff]), &selected_policy).unwrap_err(),
            SuppliedSessionLoginFormError::IneligibleResponse
        );
        assert_eq!(
            extract_supplied_session_login_csrf(
                &response(vec![b'x'; MAX_LOGIN_FORM_HTML_BYTES + 1]),
                &selected_policy,
            )
            .unwrap_err(),
            SuppliedSessionLoginFormError::IneligibleResponse
        );
    }

    #[test]
    fn requires_exactly_one_exact_path_post_form() {
        assert_eq!(
            extraction_error("<form action=\"login\" method=\"post\"></form>"),
            SuppliedSessionLoginFormError::MissingForm
        );
        assert_eq!(
            extraction_error(
                "<form action=\"https://example.test/app/login\" method=\"post\"></form>"
            ),
            SuppliedSessionLoginFormError::MissingForm
        );
        assert_eq!(
            extraction_error(&format!("{VALID_FORM}{VALID_FORM}")),
            SuppliedSessionLoginFormError::AmbiguousForm
        );
        for invalid in [
            VALID_FORM.replace("method=\"POST\"", "method=\"GET\""),
            VALID_FORM.replace("method=\"POST\"", ""),
            VALID_FORM.replace(
                "method=\"POST\"",
                "method=\"POST\" enctype=\"multipart/form-data\"",
            ),
        ] {
            assert_eq!(
                extraction_error(&invalid),
                SuppliedSessionLoginFormError::InvalidFormContract
            );
        }
    }

    #[test]
    fn rejects_duplicate_attributes_on_selected_form_and_relevant_controls() {
        let invalid_form_contracts = [
            VALID_FORM.replace(
                "action=\"/app/login\"",
                "action=\"/app/login\" action=\"/other\"",
            ),
            VALID_FORM.replace("method=\"POST\"", "method=\"POST\" method=\"GET\""),
            VALID_FORM.replace(
                "method=\"POST\"",
                "method=\"POST\" enctype=\"application/x-www-form-urlencoded\" enctype=\"multipart/form-data\"",
            ),
            VALID_FORM.replace("name=\"user\"", "name=\"user\" name=\"other\""),
            VALID_FORM.replace(
                "type=\"password\"",
                "type=\"password\" type=\"text\"",
            ),
        ];
        for invalid in invalid_form_contracts {
            assert_eq!(
                extraction_error(&invalid),
                SuppliedSessionLoginFormError::InvalidFormContract
            );
        }

        let duplicate_csrf_value = VALID_FORM.replace(
            "value=\"TOKEN-CANARY\"",
            "value=\"TOKEN-CANARY\" value=\"other\"",
        );
        assert_eq!(
            extraction_error(&duplicate_csrf_value),
            SuppliedSessionLoginFormError::InvalidCsrf
        );

        let unrelated_duplicates = format!(
            "<div class=\"first\" class=\"second\"></div>{}<input name=\"other\" value=\"first\" value=\"second\">",
            VALID_FORM.replace(
                "</form>",
                "<input name=\"other\" value=\"first\" value=\"second\"></form>"
            )
        );
        assert!(extract(&unrelated_duplicates).is_ok());
    }

    #[test]
    fn requires_exact_username_and_password_controls() {
        for invalid in [
            VALID_FORM.replace("<input name=\"user\">", ""),
            VALID_FORM.replace(
                "<input name=\"user\">",
                "<input name=\"user\"><input name=\"user\">",
            ),
            VALID_FORM.replace(
                "<input name=\"user\">",
                "<textarea name=\"user\"></textarea>",
            ),
            VALID_FORM.replace(
                "<input name=\"user\">",
                "<input type=\"email\" name=\"user\">",
            ),
            VALID_FORM.replace(
                "<input name=\"user\">",
                "<fieldset disabled><input name=\"user\"></fieldset>",
            ),
            VALID_FORM.replace("<input type=\"password\" name=\"pass\">", ""),
            VALID_FORM.replace(
                "<input type=\"password\" name=\"pass\">",
                "<input type=\"text\" name=\"pass\">",
            ),
            VALID_FORM.replace(
                "<input type=\"password\" name=\"pass\">",
                "<fieldset disabled><input type=\"password\" name=\"pass\"></fieldset>",
            ),
            VALID_FORM.replace("name=\"pass\"", "name=\"pass\" disabled"),
            VALID_FORM.replace("name=\"user\"", "name=\"user\" form=\"other\""),
        ] {
            assert_eq!(
                extraction_error(&invalid),
                SuppliedSessionLoginFormError::InvalidFormContract
            );
        }
    }

    #[test]
    fn distinguishes_missing_ambiguous_and_invalid_csrf() {
        assert_eq!(
            extraction_error(&VALID_FORM.replace(
                "<input value=\"TOKEN-CANARY\" name=\"csrf\" type=\"hidden\">",
                ""
            )),
            SuppliedSessionLoginFormError::MissingCsrf
        );
        assert_eq!(
            extraction_error(&VALID_FORM.replace(
                "</form>",
                "<input type=\"hidden\" name=\"csrf\" value=\"second\"></form>"
            )),
            SuppliedSessionLoginFormError::AmbiguousCsrf
        );
        for invalid in [
            VALID_FORM.replace("type=\"hidden\"", "type=\"text\""),
            VALID_FORM.replace("value=\"TOKEN-CANARY\"", "value=\"\""),
            VALID_FORM.replace("value=\"TOKEN-CANARY\" ", ""),
            VALID_FORM.replace("name=\"csrf\"", "name=\"csrf\" disabled"),
            VALID_FORM.replace("name=\"csrf\"", "name=\"csrf\" form=\"other\""),
            VALID_FORM.replace(
                "<input value=\"TOKEN-CANARY\" name=\"csrf\" type=\"hidden\">",
                "<fieldset disabled><input value=\"TOKEN-CANARY\" name=\"csrf\" type=\"hidden\"></fieldset>",
            ),
            VALID_FORM.replace("TOKEN-CANARY", &"x".repeat(MAX_LOGIN_CSRF_VALUE_BYTES + 1)),
        ] {
            assert_eq!(
                extraction_error(&invalid),
                SuppliedSessionLoginFormError::InvalidCsrf
            );
        }
    }

    #[test]
    fn rejects_documents_above_the_dom_node_ceiling() {
        let body = format!(
            "{}{}",
            "<i></i>".repeat(MAX_LOGIN_FORM_DOM_NODES),
            VALID_FORM
        );
        assert_eq!(
            extraction_error(&body),
            SuppliedSessionLoginFormError::InvalidFormContract
        );
    }

    #[test]
    fn overflow_handles_are_fresh_and_remain_detached() {
        let sink = BoundedLoginFormDom::new();
        for _ in 0..(MAX_LOGIN_FORM_DOM_NODES - 1) {
            let _ = sink.create_element(
                QualName::new(None, ns!(html), local_name!("i")),
                Vec::new(),
                ElementFlags::default(),
            );
        }
        assert!(!sink.limit_exceeded());
        assert_eq!(sink.retained_node_count(), MAX_LOGIN_FORM_DOM_NODES);

        let first = sink.create_element(
            QualName::new(None, ns!(html), local_name!("i")),
            Vec::new(),
            ElementFlags::default(),
        );
        let second = sink.create_element(
            QualName::new(None, ns!(html), local_name!("i")),
            Vec::new(),
            ElementFlags::default(),
        );
        assert!(sink.limit_exceeded());
        assert_eq!(sink.retained_node_count(), MAX_LOGIN_FORM_DOM_NODES);
        assert!(!sink.same_node(&first, &second));

        let document = sink.get_document();
        sink.append(&document, NodeOrText::AppendNode(first.clone()));
        assert!(document.children.borrow().is_empty());
        assert!(first.parent.take().is_none());
        assert!(second.parent.take().is_none());

        let mut flags = ElementFlags::default();
        flags.template = true;
        let template = sink.create_element(
            QualName::new(None, ns!(html), local_name!("template")),
            Vec::new(),
            flags,
        );
        let template_contents = sink.get_template_contents(&template);
        assert!(!sink.same_node(&template, &template_contents));
        assert!(template.parent.take().is_none());
        assert!(template_contents.parent.take().is_none());
    }

    #[test]
    fn form_markup_in_inert_or_foreign_content_cannot_authorize_login() {
        for body in [
            format!("<script>{VALID_FORM}</script>"),
            format!("<style>{VALID_FORM}</style>"),
            format!("<textarea>{VALID_FORM}</textarea>"),
            format!("<template>{VALID_FORM}</template>"),
            format!("<svg>{VALID_FORM}</svg>"),
            format!("<math>{VALID_FORM}</math>"),
        ] {
            assert_eq!(
                extraction_error(&body),
                SuppliedSessionLoginFormError::MissingForm
            );
        }
    }

    #[test]
    fn tree_builder_context_cannot_reassociate_table_or_select_controls() {
        let table = format!("<table>{VALID_FORM}</table>");
        let select = format!("<select>{VALID_FORM}</select>");

        assert_eq!(
            extraction_error(&table),
            SuppliedSessionLoginFormError::InvalidFormContract
        );
        assert_eq!(
            extraction_error(&select),
            SuppliedSessionLoginFormError::InvalidFormContract
        );
    }

    #[test]
    fn controls_in_another_form_cannot_complete_the_selected_form() {
        let body = format!(
            "<form action=\"/other\" method=\"post\">{}</form><form action=\"/app/login\" method=\"post\"><input type=\"hidden\" name=\"csrf\" value=\"selected\"></form>",
            "<input name=\"user\"><input type=\"password\" name=\"pass\">"
        );
        assert_eq!(
            extraction_error(&body),
            SuppliedSessionLoginFormError::InvalidFormContract
        );
    }
}
