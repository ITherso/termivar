//! Pure names-only HTML discovery for the origin assessment runtime.

use std::collections::{BTreeMap, BTreeSet};

use html5ever::{ns, parse_document as parse_html_document, tendril::TendrilSink, ParseOpts};
use markup5ever_rcdom::{Handle, NodeData, RcDom};
use url::Url;

use super::{WebAssessmentFormMethod, WebAssessmentLimits, WebAssessmentMethod};

const MAX_REFLECTION_DOM_NODES: usize = 4_096;
const MAX_REFLECTION_OCCURRENCES: usize = 32;

/// Strongest exact HTML reflection context observed in one complete bounded
/// document. No variant represents browser execution or XSS confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(in crate::web_runtime) enum ExactHtmlReflectionContext {
    Absent,
    Inert,
    Text,
    Attribute,
    Dangerous,
    /// The response is explicitly outside the HTML reflection capability.
    NotApplicable,
    /// HTML analysis could not reach a bounded, complete conclusion.
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ParsedRoute {
    pub(super) url: Url,
    pub(super) method: WebAssessmentMethod,
    pub(super) query_parameter_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ParsedForm {
    pub(super) action: Url,
    pub(super) method: WebAssessmentFormMethod,
    pub(super) query_parameter_names: Vec<String>,
    pub(super) control_names: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct ParsedDocument {
    pub(super) routes: Vec<ParsedRoute>,
    pub(super) forms: Vec<ParsedForm>,
    pub(super) route_limit_reached: bool,
    pub(super) form_limit_reached: bool,
    pub(super) control_limit_reached: bool,
    pub(super) query_name_limit_reached: bool,
    pub(super) url_byte_limit_reached: bool,
    pub(super) outside_origin_reference_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CanonicalRoot {
    pub(super) url: Url,
    pub(super) query_parameter_names: Vec<String>,
    pub(super) query_name_limit_reached: bool,
}

pub(super) fn canonicalize_root(
    target: &Url,
    limits: WebAssessmentLimits,
) -> Option<CanonicalRoot> {
    if !matches!(target.scheme(), "http" | "https")
        || !target.has_host()
        || !target.username().is_empty()
        || target.password().is_some()
    {
        return None;
    }
    let (query_parameter_names, query_name_limit_reached) =
        bounded_query_names(target, limits.max_query_parameter_names());
    let mut url = target.clone();
    url.set_fragment(None);
    url.set_query(None);
    if url.path().is_empty() {
        url.set_path("/");
    }
    (url.as_str().len() <= limits.max_canonical_url_bytes()).then_some(CanonicalRoot {
        url,
        query_parameter_names,
        query_name_limit_reached,
    })
}

pub(super) fn parse_document(
    document_url: &Url,
    html: &str,
    limits: WebAssessmentLimits,
) -> ParsedDocument {
    let dom = parse_html_document(RcDom::default(), ParseOpts::default()).one(html);
    let base_url = first_document_base(&dom.document, document_url);
    let mut routes = BTreeMap::<Url, RouteAccumulator>::new();
    let mut forms = BTreeMap::<(Url, WebAssessmentFormMethod), FormAccumulator>::new();
    let mut result = ParsedDocument::default();
    let mut pending = vec![dom.document.clone()];

    while let Some(handle) = pending.pop() {
        if let NodeData::Element { name, attrs, .. } = &handle.data {
            if name.ns == ns!(html) {
                let local = name.local.as_ref();
                if let Some((attribute, method)) = route_attribute(local) {
                    if let Some(reference) = html_attribute(attrs, attribute) {
                        match resolve_reference(&base_url, &reference, document_url, limits) {
                            ReferenceResolution::Accepted {
                                url,
                                query_parameter_names,
                                query_limit_reached,
                            } => {
                                result.query_name_limit_reached |= query_limit_reached;
                                insert_route(
                                    &mut routes,
                                    url,
                                    method,
                                    query_parameter_names,
                                    limits.max_references_per_document(),
                                    &mut result.route_limit_reached,
                                    &mut result.query_name_limit_reached,
                                );
                            },
                            ReferenceResolution::OutsideOrigin => {
                                result.outside_origin_reference_count =
                                    result.outside_origin_reference_count.saturating_add(1);
                            },
                            ReferenceResolution::UrlByteLimit => {
                                result.url_byte_limit_reached = true;
                            },
                            ReferenceResolution::Inert => {},
                        }
                    }
                } else if local == "form" {
                    if let Some(form) =
                        parse_form(&handle, document_url, &base_url, limits, &mut result)
                    {
                        // GET form actions are safe route candidates, but they
                        // share the same deterministic per-document route
                        // ceiling as anchors, areas, and links.
                        if form.method == WebAssessmentFormMethod::Get {
                            insert_route(
                                &mut routes,
                                form.action.clone(),
                                WebAssessmentMethod::Get,
                                form.query_parameter_names.clone(),
                                limits.max_references_per_document(),
                                &mut result.route_limit_reached,
                                &mut result.query_name_limit_reached,
                            );
                        }
                        insert_form(
                            &mut forms,
                            form,
                            limits.max_forms(),
                            &mut result.form_limit_reached,
                            &mut result.control_limit_reached,
                            &mut result.query_name_limit_reached,
                        );
                    }
                }
            }
        }
        pending.extend(handle.children.borrow().iter().rev().cloned());
    }

    result.routes = routes
        .into_iter()
        .map(|(url, route)| {
            let query_limit_reached =
                route.query_parameter_names.len() > limits.max_query_parameter_names();
            result.query_name_limit_reached |= query_limit_reached;
            ParsedRoute {
                url,
                method: route.method,
                query_parameter_names: route
                    .query_parameter_names
                    .into_iter()
                    .take(limits.max_query_parameter_names())
                    .collect(),
            }
        })
        .collect();
    result.forms = forms
        .into_iter()
        .map(|((action, method), form)| {
            let query_limit_reached =
                form.query_parameter_names.len() > limits.max_query_parameter_names();
            let control_limit_reached = form.control_names.len() > limits.max_controls_per_form();
            result.query_name_limit_reached |= query_limit_reached;
            result.control_limit_reached |= control_limit_reached;
            ParsedForm {
                action,
                method,
                query_parameter_names: form
                    .query_parameter_names
                    .into_iter()
                    .take(limits.max_query_parameter_names())
                    .collect(),
                control_names: form
                    .control_names
                    .into_iter()
                    .take(limits.max_controls_per_form())
                    .collect(),
            }
        })
        .collect();
    result
}

/// Classifies an exact candidate reflection with the same standards-compliant
/// DOM parser used by discovery. Traversal and occurrence counts are hard
/// bounded; an exhausted bound is explicitly inconclusive and cannot emit an
/// assessment item.
pub(in crate::web_runtime) fn classify_exact_html_reflection(
    html: &str,
    candidate: &str,
) -> ExactHtmlReflectionContext {
    if candidate.is_empty() {
        return ExactHtmlReflectionContext::Incomplete;
    }
    let dom = parse_html_document(RcDom::default(), ParseOpts::default()).one(html);
    let mut pending = vec![(dom.document.clone(), false)];
    let mut nodes = 0_usize;
    let mut occurrences = 0_usize;
    let mut strongest = ExactHtmlReflectionContext::Absent;

    while let Some((handle, dangerous_parent)) = pending.pop() {
        nodes = nodes.saturating_add(1);
        if nodes > MAX_REFLECTION_DOM_NODES {
            return ExactHtmlReflectionContext::Incomplete;
        }
        let mut child_dangerous = dangerous_parent;
        match &handle.data {
            NodeData::Element { name, attrs, .. } if name.ns == ns!(html) => {
                let local = name.local.as_ref();
                child_dangerous = dangerous_parent || matches!(local, "script" | "style");
                for attribute in attrs.borrow().iter() {
                    let value = attribute.value.as_ref();
                    let count = value
                        .match_indices(candidate)
                        .take(
                            MAX_REFLECTION_OCCURRENCES
                                .saturating_sub(occurrences)
                                .saturating_add(1),
                        )
                        .count();
                    occurrences = occurrences.saturating_add(count);
                    if occurrences > MAX_REFLECTION_OCCURRENCES {
                        return ExactHtmlReflectionContext::Incomplete;
                    }
                    if count == 0 {
                        continue;
                    }
                    let attribute_name = attribute.name.local.as_ref();
                    let context = if child_dangerous
                        || attribute_name.starts_with("on")
                        || matches!(attribute_name, "srcdoc" | "style")
                        || matches!(
                            attribute_name,
                            "href"
                                | "src"
                                | "action"
                                | "formaction"
                                | "poster"
                                | "data"
                                | "xlink:href"
                        ) {
                        ExactHtmlReflectionContext::Dangerous
                    } else {
                        ExactHtmlReflectionContext::Attribute
                    };
                    strongest = strongest.max(context);
                }
            },
            NodeData::Text { contents } => {
                let contents = contents.borrow();
                let count = contents
                    .match_indices(candidate)
                    .take(
                        MAX_REFLECTION_OCCURRENCES
                            .saturating_sub(occurrences)
                            .saturating_add(1),
                    )
                    .count();
                occurrences = occurrences.saturating_add(count);
                if occurrences > MAX_REFLECTION_OCCURRENCES {
                    return ExactHtmlReflectionContext::Incomplete;
                }
                if count != 0 {
                    strongest = strongest.max(if dangerous_parent {
                        ExactHtmlReflectionContext::Dangerous
                    } else {
                        ExactHtmlReflectionContext::Text
                    });
                }
            },
            NodeData::Comment { contents } => {
                let count = contents
                    .match_indices(candidate)
                    .take(
                        MAX_REFLECTION_OCCURRENCES
                            .saturating_sub(occurrences)
                            .saturating_add(1),
                    )
                    .count();
                occurrences = occurrences.saturating_add(count);
                if occurrences > MAX_REFLECTION_OCCURRENCES {
                    return ExactHtmlReflectionContext::Incomplete;
                }
                if count != 0 {
                    strongest = strongest.max(ExactHtmlReflectionContext::Inert);
                }
            },
            _ => {},
        }
        pending.extend(
            handle
                .children
                .borrow()
                .iter()
                .rev()
                .cloned()
                .map(|child| (child, child_dangerous)),
        );
    }
    strongest
}

fn route_attribute(local: &str) -> Option<(&'static str, WebAssessmentMethod)> {
    match local {
        "a" | "area" => Some(("href", WebAssessmentMethod::Get)),
        "link" => Some(("href", WebAssessmentMethod::Head)),
        _ => None,
    }
}

fn first_document_base(root: &Handle, document_url: &Url) -> Url {
    let mut pending = vec![root.clone()];
    while let Some(handle) = pending.pop() {
        if let NodeData::Element { name, attrs, .. } = &handle.data {
            if name.ns == ns!(html) && name.local.as_ref() == "base" {
                if let Some(reference) = html_attribute(attrs, "href") {
                    // The first base-with-href wins. A malformed, credentialed,
                    // or unsupported value falls back; a later base never
                    // rescues it.
                    return document_url
                        .join(reference.trim())
                        .ok()
                        .filter(supported_uncredentialed_url)
                        .unwrap_or_else(|| document_url.clone());
                }
            }
        }
        pending.extend(handle.children.borrow().iter().rev().cloned());
    }
    document_url.clone()
}

fn parse_form(
    handle: &Handle,
    document_url: &Url,
    base_url: &Url,
    limits: WebAssessmentLimits,
    result: &mut ParsedDocument,
) -> Option<ParsedForm> {
    let (reference, method) = match &handle.data {
        NodeData::Element { attrs, .. } => {
            let reference = html_attribute(attrs, "action").unwrap_or_default();
            let method = match html_attribute(attrs, "method") {
                Some(value) if value.eq_ignore_ascii_case("post") => WebAssessmentFormMethod::Post,
                Some(value) if value.eq_ignore_ascii_case("dialog") => {
                    WebAssessmentFormMethod::Dialog
                },
                _ => WebAssessmentFormMethod::Get,
            };
            (reference, method)
        },
        _ => return None,
    };
    let resolution_base = if reference.trim().is_empty() {
        document_url
    } else {
        base_url
    };
    let reference = if reference.trim().is_empty() {
        document_url.as_str()
    } else {
        reference.trim()
    };
    let (action, query_parameter_names) =
        match resolve_reference(resolution_base, reference, document_url, limits) {
            ReferenceResolution::Accepted {
                url,
                query_parameter_names,
                query_limit_reached,
            } => {
                result.query_name_limit_reached |= query_limit_reached;
                (url, query_parameter_names)
            },
            ReferenceResolution::OutsideOrigin => {
                result.outside_origin_reference_count =
                    result.outside_origin_reference_count.saturating_add(1);
                return None;
            },
            ReferenceResolution::UrlByteLimit => {
                result.url_byte_limit_reached = true;
                return None;
            },
            ReferenceResolution::Inert => return None,
        };

    let mut controls = BTreeSet::new();
    let mut pending: Vec<Handle> = handle.children.borrow().iter().rev().cloned().collect();
    while let Some(child) = pending.pop() {
        if let NodeData::Element { name, attrs, .. } = &child.data {
            if name.ns == ns!(html) && name.local.as_ref() == "form" {
                continue;
            }
            if name.ns == ns!(html)
                && matches!(
                    name.local.as_ref(),
                    "input" | "select" | "textarea" | "button"
                )
                && html_attribute(attrs, "form").is_none()
            {
                if let Some(control_name) = html_attribute(attrs, "name") {
                    match name_disposition(&control_name) {
                        NameDisposition::Accepted => {
                            controls.insert(control_name);
                            if controls.len() > super::HARD_MAX_DISCOVERY_NAMES_PER_REFERENCE {
                                controls.pop_last();
                                result.control_limit_reached = true;
                            }
                        },
                        NameDisposition::TooLong => result.control_limit_reached = true,
                        NameDisposition::Inert => {},
                    }
                }
            }
        }
        pending.extend(child.children.borrow().iter().rev().cloned());
    }
    Some(ParsedForm {
        action,
        method,
        query_parameter_names,
        control_names: controls.into_iter().collect(),
    })
}

struct RouteAccumulator {
    method: WebAssessmentMethod,
    query_parameter_names: BTreeSet<String>,
}

struct FormAccumulator {
    query_parameter_names: BTreeSet<String>,
    control_names: BTreeSet<String>,
}

fn insert_route(
    routes: &mut BTreeMap<Url, RouteAccumulator>,
    url: Url,
    method: WebAssessmentMethod,
    query_parameter_names: Vec<String>,
    limit: usize,
    limit_reached: &mut bool,
    query_limit_reached: &mut bool,
) {
    if let Some(route) = routes.get_mut(&url) {
        if method == WebAssessmentMethod::Get {
            route.method = WebAssessmentMethod::Get;
        }
        *query_limit_reached |=
            merge_names(&mut route.query_parameter_names, query_parameter_names);
        return;
    }
    if limit == 0 {
        *limit_reached = true;
        return;
    }
    routes.insert(
        url,
        RouteAccumulator {
            method,
            query_parameter_names: query_parameter_names.into_iter().collect(),
        },
    );
    if routes.len() > limit {
        routes.pop_last();
        *limit_reached = true;
    }
}

fn insert_form(
    forms: &mut BTreeMap<(Url, WebAssessmentFormMethod), FormAccumulator>,
    form: ParsedForm,
    limit: usize,
    limit_reached: &mut bool,
    control_limit_reached: &mut bool,
    query_limit_reached: &mut bool,
) {
    let key = (form.action, form.method);
    if let Some(existing) = forms.get_mut(&key) {
        *query_limit_reached |= merge_names(
            &mut existing.query_parameter_names,
            form.query_parameter_names,
        );
        *control_limit_reached |= merge_names(&mut existing.control_names, form.control_names);
        return;
    }
    if limit == 0 {
        *limit_reached = true;
        return;
    }
    forms.insert(
        key,
        FormAccumulator {
            query_parameter_names: form.query_parameter_names.into_iter().collect(),
            control_names: form.control_names.into_iter().collect(),
        },
    );
    if forms.len() > limit {
        forms.pop_last();
        *limit_reached = true;
    }
}

fn merge_names(target: &mut BTreeSet<String>, names: impl IntoIterator<Item = String>) -> bool {
    let mut limit_reached = false;
    for name in names {
        target.insert(name);
        if target.len() > super::HARD_MAX_DISCOVERY_NAMES_PER_REFERENCE {
            target.pop_last();
            limit_reached = true;
        }
    }
    limit_reached
}

enum ReferenceResolution {
    Accepted {
        url: Url,
        query_parameter_names: Vec<String>,
        query_limit_reached: bool,
    },
    OutsideOrigin,
    UrlByteLimit,
    Inert,
}

fn resolve_reference(
    base_url: &Url,
    raw_reference: &str,
    authorized_url: &Url,
    limits: WebAssessmentLimits,
) -> ReferenceResolution {
    let reference = raw_reference.trim();
    if reference.len() > limits.max_canonical_url_bytes() {
        return ReferenceResolution::UrlByteLimit;
    }
    let Ok(mut url) = base_url.join(reference) else {
        return ReferenceResolution::Inert;
    };
    if !supported_uncredentialed_url(&url) {
        return ReferenceResolution::Inert;
    }
    if url.origin() != authorized_url.origin() {
        return ReferenceResolution::OutsideOrigin;
    }
    let (query_parameter_names, hard_query_limit_reached) =
        bounded_query_names(&url, super::HARD_MAX_DISCOVERY_NAMES_PER_REFERENCE);
    let query_limit_reached = hard_query_limit_reached
        || query_parameter_names.len() > limits.max_query_parameter_names();
    url.set_fragment(None);
    url.set_query(None);
    if url.path().is_empty() {
        url.set_path("/");
    }
    if url.as_str().len() > limits.max_canonical_url_bytes() {
        return ReferenceResolution::UrlByteLimit;
    }
    ReferenceResolution::Accepted {
        url,
        query_parameter_names,
        query_limit_reached,
    }
}

fn bounded_query_names(url: &Url, limit: usize) -> (Vec<String>, bool) {
    let mut names = BTreeSet::new();
    let mut hard_limit_reached = false;
    for name in url.query_pairs().map(|(name, _)| name.into_owned()) {
        match name_disposition(&name) {
            NameDisposition::Accepted => {
                names.insert(name);
                if names.len() > super::HARD_MAX_DISCOVERY_NAMES_PER_REFERENCE {
                    names.pop_last();
                    hard_limit_reached = true;
                }
            },
            NameDisposition::TooLong => hard_limit_reached = true,
            NameDisposition::Inert => {},
        }
    }
    let limit_reached = hard_limit_reached || names.len() > limit;
    (names.into_iter().take(limit).collect(), limit_reached)
}

fn supported_uncredentialed_url(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url.has_host()
        && url.username().is_empty()
        && url.password().is_none()
}

enum NameDisposition {
    Accepted,
    TooLong,
    Inert,
}

fn name_disposition(name: &str) -> NameDisposition {
    if name.is_empty() || name.chars().any(char::is_control) {
        NameDisposition::Inert
    } else if name.len() > super::HARD_MAX_DISCOVERY_NAME_BYTES {
        NameDisposition::TooLong
    } else {
        NameDisposition::Accepted
    }
}

fn html_attribute(
    attrs: &std::cell::RefCell<Vec<html5ever::Attribute>>,
    local_name: &str,
) -> Option<String> {
    attrs
        .borrow()
        .iter()
        .find(|attr| attr.name.ns == ns!() && attr.name.local.as_ref() == local_name)
        .map(|attr| attr.value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(path: &str) -> Url {
        Url::parse(&format!("https://example.test{path}")).unwrap()
    }

    #[test]
    fn parser_normalizes_routes_and_never_retains_values() {
        let parsed = parse_document(
            &target("/a/index"),
            r#"
                <a href="../next?token=secret&z=2&a=1#part">next</a>
                <a href="https://example.test/next?a=other&token=changed">duplicate</a>
                <link href="/asset.css?cache=private" rel="stylesheet">
                <a href="https://other.test/private?token=leak">outside</a>
            "#,
            WebAssessmentLimits::default(),
        );

        assert_eq!(parsed.outside_origin_reference_count, 1);
        assert_eq!(parsed.routes.len(), 2);
        assert!(parsed
            .routes
            .iter()
            .all(|route| route.url.query().is_none()));
        assert!(parsed
            .routes
            .iter()
            .all(|route| !format!("{route:?}").contains("secret")));
        assert!(parsed.routes.iter().any(|route| {
            route.url == target("/next") && route.query_parameter_names == ["a", "token", "z"]
        }));
        assert!(parsed.routes.iter().any(|route| {
            route.url == target("/asset.css") && route.method == WebAssessmentMethod::Head
        }));
    }

    #[test]
    fn forms_keep_names_only_and_post_dialog_are_not_routes() {
        let parsed = parse_document(
            &target("/root"),
            r#"
                <form action="/search?q=secret" method="get">
                  <input name="q" value="do-not-retain">
                  <input name="csrf" value="private">
                </form>
                <form action="/write?token=private" method="post"><input name="title"></form>
                <form action="/modal" method="dialog"><button name="accept">ok</button></form>
            "#,
            WebAssessmentLimits::default(),
        );

        assert_eq!(parsed.forms.len(), 3);
        assert_eq!(
            parsed
                .forms
                .iter()
                .find(|form| form.method == WebAssessmentFormMethod::Get)
                .unwrap()
                .control_names,
            ["csrf", "q"]
        );
        assert!(format!("{parsed:?}").contains("token")); // query name is retained
        assert!(!format!("{parsed:?}").contains("private"));
        assert!(!format!("{parsed:?}").contains("do-not-retain"));
    }

    #[test]
    fn malformed_html_is_recovered_deterministically() {
        let first = parse_document(
            &target("/"),
            "<a href='/b'><form action=/s><input name=q><a href='/a'",
            WebAssessmentLimits::default(),
        );
        let second = parse_document(
            &target("/"),
            "<a href='/b'><form action=/s><input name=q><a href='/a'",
            WebAssessmentLimits::default(),
        );
        assert_eq!(first, second);
    }

    #[test]
    fn shuffled_duplicate_routes_merge_before_the_stable_prefix() {
        let first = parse_document(
            &target("/"),
            "<link href='/same?z=1'><a href='/same?a=2'><a href='/b'>",
            WebAssessmentLimits::default(),
        );
        let second = parse_document(
            &target("/"),
            "<a href='/b'><a href='/same?a=x'><link href='/same?z=y'>",
            WebAssessmentLimits::default(),
        );

        assert_eq!(first, second);
        assert_eq!(first.routes.len(), 2);
        let same = first
            .routes
            .iter()
            .find(|route| route.url == target("/same"))
            .unwrap();
        assert_eq!(same.method, WebAssessmentMethod::Get);
        assert_eq!(same.query_parameter_names, ["a", "z"]);
    }

    #[test]
    fn duplicate_forms_union_names_and_form_limit_is_a_sorted_prefix() {
        let limits = WebAssessmentLimits::default().with_max_forms(1).unwrap();
        let first = parse_document(
            &target("/"),
            "<form action='/z' method=post><input name=z></form>\
             <form action='/a?q=1' method=post><input name=b></form>\
             <form action='/a?r=2' method=post><input name=a></form>",
            limits,
        );
        let second = parse_document(
            &target("/"),
            "<form action='/a?r=x' method=post><input name=a></form>\
             <form action='/z' method=post><input name=z></form>\
             <form action='/a?q=y' method=post><input name=b></form>",
            limits,
        );

        assert_eq!(first, second);
        assert!(first.form_limit_reached);
        assert_eq!(first.forms.len(), 1);
        assert_eq!(first.forms[0].action, target("/a"));
        assert_eq!(first.forms[0].query_parameter_names, ["q", "r"]);
        assert_eq!(first.forms[0].control_names, ["a", "b"]);
    }

    #[test]
    fn get_forms_share_the_route_prefix_but_post_and_dialog_never_become_routes() {
        let limits = WebAssessmentLimits::default()
            .with_max_references_per_document(1)
            .unwrap();
        let parsed = parse_document(
            &target("/"),
            "<a href='/z'>\
             <form action='/a?q=secret' method=get><input name=q></form>\
             <form action='/post' method=post><input name=p></form>\
             <form action='/dialog' method=dialog><button name=d></button></form>",
            limits,
        );

        assert!(parsed.route_limit_reached);
        assert_eq!(parsed.routes.len(), 1);
        assert_eq!(parsed.routes[0].url, target("/a"));
        assert_eq!(parsed.routes[0].method, WebAssessmentMethod::Get);
        assert!(!parsed
            .routes
            .iter()
            .any(|route| { matches!(route.url.path(), "/post" | "/dialog") }));
    }

    #[test]
    fn executable_and_embedded_asset_tags_are_not_route_candidates() {
        let parsed = parse_document(
            &target("/"),
            "<iframe src='/frame'></iframe><script src='/script'></script>\
             <img src='/img'><source src='/source'><video src='/video'></video>\
             <audio src='/audio'></audio><a href='/allowed'>",
            WebAssessmentLimits::default(),
        );

        assert_eq!(parsed.routes.len(), 1);
        assert_eq!(parsed.routes[0].url, target("/allowed"));
    }

    #[test]
    fn huge_duplicate_markup_keeps_only_bounded_deterministic_state() {
        let limits = WebAssessmentLimits::default()
            .with_max_references_per_document(2)
            .unwrap();
        let html = (0..10_000)
            .rev()
            .map(|index| format!("<a href='/route-{index:05}?name=value'>"))
            .collect::<String>();
        let parsed = parse_document(&target("/"), &html, limits);

        assert!(parsed.route_limit_reached);
        assert_eq!(parsed.routes.len(), 2);
        assert_eq!(parsed.routes[0].url, target("/route-00000"));
        assert_eq!(parsed.routes[1].url, target("/route-00001"));
    }

    #[test]
    fn canonical_root_rejects_credentials_and_strips_query_values() {
        let credentialed = Url::parse("https://user:secret@example.test/?a=value").unwrap();
        assert!(canonicalize_root(&credentialed, WebAssessmentLimits::default()).is_none());

        let root = canonicalize_root(
            &Url::parse("https://example.test/a/../?z=secret&a=private#fragment").unwrap(),
            WebAssessmentLimits::default(),
        )
        .unwrap();
        assert_eq!(root.url, target("/"));
        assert_eq!(root.query_parameter_names, ["a", "z"]);
        assert!(!format!("{root:?}").contains("secret"));
        assert!(!format!("{root:?}").contains("private"));
    }

    #[test]
    fn exact_reflection_contexts_are_parser_classified_without_execution_claims() {
        let candidate = "https://case.review.invalid/";
        for (html, expected) in [
            (
                "<p>no candidate here</p>",
                ExactHtmlReflectionContext::Absent,
            ),
            (
                "<!-- https://case.review.invalid/ -->",
                ExactHtmlReflectionContext::Inert,
            ),
            (
                "<p>https://case.review.invalid/</p>",
                ExactHtmlReflectionContext::Text,
            ),
            (
                "<div data-next='https://case.review.invalid/'></div>",
                ExactHtmlReflectionContext::Attribute,
            ),
            (
                "<a href='https://case.review.invalid/'>continue</a>",
                ExactHtmlReflectionContext::Dangerous,
            ),
            (
                "<div onclick='go(&quot;https://case.review.invalid/&quot;)'></div>",
                ExactHtmlReflectionContext::Dangerous,
            ),
            (
                "<script>const next = 'https://case.review.invalid/';</script>",
                ExactHtmlReflectionContext::Dangerous,
            ),
        ] {
            assert_eq!(classify_exact_html_reflection(html, candidate), expected);
        }
    }

    #[test]
    fn exact_reflection_classification_is_deterministic_and_fail_closed_at_limits() {
        let candidate = "https://case.review.invalid/";
        let ordinary = format!("<p>{candidate}</p>");
        assert_eq!(
            classify_exact_html_reflection(&ordinary, candidate),
            classify_exact_html_reflection(&ordinary, candidate)
        );
        assert_eq!(
            classify_exact_html_reflection(&ordinary, ""),
            ExactHtmlReflectionContext::Incomplete
        );

        let too_many = std::iter::repeat_n(candidate, MAX_REFLECTION_OCCURRENCES + 1)
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            classify_exact_html_reflection(&format!("<p>{too_many}</p>"), candidate),
            ExactHtmlReflectionContext::Incomplete
        );

        let too_many_nodes = (0..=MAX_REFLECTION_DOM_NODES)
            .map(|_| "<span></span>")
            .collect::<String>();
        assert_eq!(
            classify_exact_html_reflection(&too_many_nodes, candidate),
            ExactHtmlReflectionContext::Incomplete
        );
    }
}
