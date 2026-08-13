//! # Phase 2: bounded same-origin discovery
//!
//! This legacy phase discovers a finite set of HTTP endpoints and form-control
//! names. A host-owned discovery request broker supplies the transport bounds;
//! this module supplies deterministic breadth-first traversal, URL
//! canonicalization, standards-aware HTML parsing, and atomic state staging.

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

use crate::{
    context::ScanContext,
    contracts::{ScanFinding, ScanPhase},
    error::ScannerError,
    http_evidence::HttpProbeMethod,
    legacy_discovery::{DiscoveryDelta, DiscoveryForm, DiscoveryFormMethod},
};
use async_trait::async_trait;
use html5ever::{ns, parse_document, tendril::TendrilSink, ParseOpts};
use markup5ever_rcdom::{Handle, NodeData, RcDom};
use url::Url;

const CRAWL_ACTION_ID: &str = "legacy.discovery.crawl";
const MAX_REFERENCES_PER_PAGE: usize = 1_024;
const MAX_FORMS_PER_PAGE: usize = 256;
const MAX_CONTROLS_PER_FORM: usize = 256;
const MAX_CRAWLER_HTML_PARSE_BYTES: usize = 64 * 1024;
const MAX_DISCOVERY_NAME_BYTES: usize = 1_024;
const MAX_DISCOVERED_ENDPOINTS: usize = 4_096;
const MAX_DISCOVERED_FORMS: usize = 1_024;

/// Web crawling phase for bounded endpoint and parameter discovery.
#[derive(Debug)]
pub struct CrawlPhase;

#[async_trait]
impl ScanPhase for CrawlPhase {
    fn phase_number(&self) -> u8 {
        2
    }

    fn name(&self) -> &'static str {
        "Web Crawler & Parameter Discovery"
    }

    async fn execute(&self, ctx: &ScanContext) -> Result<Vec<ScanFinding>, ScannerError> {
        ctx.log("Phase 2: bounded same-origin crawler initiated".to_string());

        let limits = ctx.discovery_limits();
        let discovery = crawl_with_broker(
            ctx,
            CrawlPolicy {
                max_depth: limits.max_depth(),
                max_pages: limits.max_pages(),
            },
        )
        .await?;
        let endpoint_count = discovery.endpoint_count();
        let form_count = discovery.form_count();
        discovery.commit(ctx)?;

        ctx.log(format!(
            "Phase 2: bounded crawl completed with {endpoint_count} endpoints and {form_count} forms"
        ));
        Ok(Vec::new())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CrawlPolicy {
    max_depth: usize,
    max_pages: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FormMethod {
    Get,
    Post,
    Dialog,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DiscoveredForm {
    action: Url,
    method: FormMethod,
    controls: Vec<String>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ParsedDocument {
    links: Vec<Url>,
    forms: Vec<DiscoveredForm>,
}

#[derive(Debug, Default)]
struct CrawlDiscovery {
    endpoints: BTreeMap<String, BTreeSet<String>>,
    visited: BTreeSet<String>,
    forms: BTreeSet<DiscoveredForm>,
}

impl CrawlDiscovery {
    fn register_endpoint(&mut self, url: &Url) {
        let params = query_parameter_names(url);
        self.endpoints
            .entry(url.as_str().to_string())
            .or_default()
            .extend(params);
    }

    fn register_get_form(&mut self, form: &DiscoveredForm) {
        let params = self
            .endpoints
            .entry(form.action.as_str().to_string())
            .or_default();
        params.extend(query_parameter_names(&form.action));
        params.extend(form.controls.iter().cloned());
    }

    fn endpoint_count(&self) -> usize {
        self.endpoints.len()
    }

    fn form_count(&self) -> usize {
        self.forms.len()
    }

    fn commit(self, ctx: &ScanContext) -> Result<(), ScannerError> {
        let mut delta = DiscoveryDelta::new();
        for (url, params) in self.endpoints {
            delta.record_endpoint(Url::parse(&url)?, params);
        }
        for url in self.visited {
            delta.record_visited(Url::parse(&url)?);
        }
        for form in self.forms {
            delta.record_form(DiscoveryForm::new(
                form.action,
                match form.method {
                    FormMethod::Get => DiscoveryFormMethod::Get,
                    FormMethod::Post => DiscoveryFormMethod::Post,
                    FormMethod::Dialog => DiscoveryFormMethod::Dialog,
                },
                form.controls,
            )?);
        }
        ctx.commit_discovery(CRAWL_ACTION_ID, delta)
    }
}

async fn crawl_with_broker(
    ctx: &ScanContext,
    policy: CrawlPolicy,
) -> Result<CrawlDiscovery, ScannerError> {
    let root = ctx.canonicalize_discovery_url(&ctx.target)?;
    let visited_before_crawl = ctx.discovery_snapshot().visited().clone();
    let mut discovery = CrawlDiscovery::default();
    discovery.register_endpoint(&root);

    if policy.max_pages == 0 {
        return Ok(discovery);
    }

    let mut queue = VecDeque::new();
    if !visited_before_crawl.contains(root.as_str()) {
        queue.push_back((root.clone(), 0_usize));
    }
    let mut scheduled = BTreeSet::from([root.as_str().to_string()]);

    while let Some((page_url, depth)) = queue.pop_front() {
        let response = ctx
            .request(CRAWL_ACTION_ID, HttpProbeMethod::Get, page_url.clone())
            .await?;
        let requested = ctx.canonicalize_discovery_url(response.request_url())?;
        let final_url = ctx.canonicalize_discovery_url(response.final_url())?;
        if requested != page_url || final_url != page_url {
            return Err(ScannerError::InvalidTarget);
        }
        discovery.visited.insert(page_url.as_str().to_string());

        // Redirects are observations, not crawler navigation authority. The
        // broker never follows them and the crawler never consumes Location.
        if (300..400).contains(&response.status())
            || response.body_truncated()
            || response.body().len() > MAX_CRAWLER_HTML_PARSE_BYTES
            || !response
                .content_type()
                .is_some_and(supported_html_media_type)
        {
            continue;
        }

        let parsed = parse_html_document(&page_url, response.body());
        let mut candidates = Vec::new();
        for link in parsed.links {
            let Some(candidate) = canonical_same_origin(ctx, &root, link)? else {
                continue;
            };
            candidates.push((candidate, None));
        }

        for form in parsed.forms {
            let Some(action) = canonical_same_origin(ctx, &root, form.action.clone())? else {
                continue;
            };
            candidates.push((action.clone(), Some(DiscoveredForm { action, ..form })));
        }
        candidates.sort_by(|(left_url, left_form), (right_url, right_form)| {
            left_url
                .as_str()
                .cmp(right_url.as_str())
                .then_with(|| form_method_rank(left_form).cmp(&form_method_rank(right_form)))
                .then_with(|| {
                    left_form
                        .as_ref()
                        .map(|form| form.controls.as_slice())
                        .cmp(&right_form.as_ref().map(|form| form.controls.as_slice()))
                })
        });

        for (candidate, form) in candidates {
            let Some(form) = form else {
                if schedule_page(
                    &mut queue,
                    &mut scheduled,
                    &visited_before_crawl,
                    candidate.clone(),
                    depth,
                    policy,
                ) {
                    discovery.register_endpoint(&candidate);
                }
                continue;
            };
            bounded_insert(&mut discovery.forms, form.clone(), MAX_DISCOVERED_FORMS);
            match form.method {
                FormMethod::Get => {
                    if schedule_page(
                        &mut queue,
                        &mut scheduled,
                        &visited_before_crawl,
                        candidate,
                        depth,
                        policy,
                    ) {
                        discovery.register_get_form(&form);
                    }
                },
                FormMethod::Post | FormMethod::Dialog => {},
            }
        }
    }

    Ok(discovery)
}

fn form_method_rank(form: &Option<DiscoveredForm>) -> u8 {
    match form.as_ref().map(|form| form.method) {
        None => 0,
        Some(FormMethod::Get) => 1,
        Some(FormMethod::Post) => 2,
        Some(FormMethod::Dialog) => 3,
    }
}

fn canonical_same_origin(
    ctx: &ScanContext,
    root: &Url,
    candidate: Url,
) -> Result<Option<Url>, ScannerError> {
    if !candidate.username().is_empty() || candidate.password().is_some() {
        return Ok(None);
    }
    let Some(candidate) = resolve_same_origin(root, candidate.as_str(), root) else {
        return Ok(None);
    };
    ctx.canonicalize_discovery_url(&candidate).map(Some)
}

fn schedule_page(
    queue: &mut VecDeque<(Url, usize)>,
    scheduled: &mut BTreeSet<String>,
    visited_before_crawl: &BTreeSet<String>,
    candidate: Url,
    parent_depth: usize,
    policy: CrawlPolicy,
) -> bool {
    if scheduled.contains(candidate.as_str()) {
        return true;
    }

    let page_limit = policy.max_pages.min(MAX_DISCOVERED_ENDPOINTS);
    if parent_depth >= policy.max_depth || scheduled.len() >= page_limit {
        return false;
    }

    scheduled.insert(candidate.as_str().to_string());
    if !visited_before_crawl.contains(candidate.as_str()) {
        queue.push_back((candidate, parent_depth + 1));
    }
    true
}

fn supported_html_media_type(content_type: &str) -> bool {
    let media_type = content_type.split(';').next().unwrap_or_default().trim();
    media_type.eq_ignore_ascii_case("text/html")
}

fn canonicalize_url(mut url: Url) -> Url {
    url.set_fragment(None);
    if url.path().is_empty() {
        url.set_path("/");
    }

    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    if pairs.is_empty() {
        url.set_query(None);
        return url;
    }

    // Reordering repeated names can change first/last-value application
    // semantics. Only canonicalize ordering when every parameter name is
    // unique; otherwise preserve the encoded request order exactly.
    let mut names = HashSet::with_capacity(pairs.len());
    if pairs.iter().all(|(name, _)| names.insert(name.clone())) {
        let mut sorted = pairs;
        sorted.sort();
        url.query_pairs_mut().clear().extend_pairs(sorted);
    }
    url
}

fn resolve_same_origin(base: &Url, reference: &str, authorized_origin: &Url) -> Option<Url> {
    let resolved = base.join(reference).ok()?;
    if !matches!(resolved.scheme(), "http" | "https")
        || !resolved.username().is_empty()
        || resolved.password().is_some()
        || !same_origin(authorized_origin, &resolved)
    {
        return None;
    }
    Some(canonicalize_url(resolved))
}

fn same_origin(target: &Url, candidate: &Url) -> bool {
    target.origin() == candidate.origin()
}

fn query_parameter_names(url: &Url) -> BTreeSet<String> {
    url.query_pairs()
        .filter_map(|(name, _)| {
            (!name.is_empty() && name.len() <= MAX_DISCOVERY_NAME_BYTES).then(|| name.into_owned())
        })
        .collect()
}

fn bounded_insert<T: Ord>(values: &mut BTreeSet<T>, value: T, limit: usize) {
    if limit == 0 || !values.insert(value) {
        return;
    }
    if values.len() > limit {
        values.pop_last();
    }
}

fn parse_html_document(document_url: &Url, html: &[u8]) -> ParsedDocument {
    let dom = parse_document(RcDom::default(), ParseOpts::default())
        .from_utf8()
        .one(html);
    let base_url = first_document_base(&dom.document, document_url);
    let mut links = BTreeSet::new();
    let mut forms = BTreeSet::new();
    let mut pending = vec![dom.document.clone()];

    while let Some(handle) = pending.pop() {
        if let NodeData::Element { name, attrs, .. } = &handle.data {
            if name.ns == ns!(html) && name.local.as_ref() == "a" {
                if let Some(reference) = html_attribute(attrs, "href") {
                    if let Ok(url) = base_url.join(&reference) {
                        bounded_insert(&mut links, canonicalize_url(url), MAX_REFERENCES_PER_PAGE);
                    }
                }
            } else if name.ns == ns!(html) && name.local.as_ref() == "form" {
                if let Some(form) = parse_form(&handle, document_url, &base_url) {
                    bounded_insert(&mut forms, form, MAX_FORMS_PER_PAGE);
                }
            }
        }
        pending.extend(handle.children.borrow().iter().rev().cloned());
    }

    ParsedDocument {
        links: links.into_iter().collect(),
        forms: forms.into_iter().collect(),
    }
}

fn first_document_base(root: &Handle, document_url: &Url) -> Url {
    let mut pending = vec![root.clone()];
    while let Some(handle) = pending.pop() {
        if let NodeData::Element { name, attrs, .. } = &handle.data {
            if name.ns == ns!(html) && name.local.as_ref() == "base" {
                if let Some(reference) = html_attribute(attrs, "href") {
                    // HTML freezes URL resolution at the first base element
                    // with an `href`. A malformed first value falls back to the
                    // document URL; a later base must not rescue it.
                    return document_url
                        .join(&reference)
                        .ok()
                        .filter(|url| matches!(url.scheme(), "http" | "https"))
                        .unwrap_or_else(|| document_url.clone());
                }
            }
        }
        pending.extend(handle.children.borrow().iter().rev().cloned());
    }
    document_url.clone()
}

fn parse_form(handle: &Handle, document_url: &Url, base_url: &Url) -> Option<DiscoveredForm> {
    let (action, method) = match &handle.data {
        NodeData::Element { attrs, .. } => {
            let action = match html_attribute(attrs, "action") {
                None => document_url.clone(),
                Some(value) if value.trim().is_empty() => document_url.clone(),
                Some(value) => base_url
                    .join(value.trim())
                    .ok()
                    .filter(|url| matches!(url.scheme(), "http" | "https"))?,
            };
            let method = match html_attribute(attrs, "method") {
                Some(value) if value.eq_ignore_ascii_case("post") => FormMethod::Post,
                Some(value) if value.eq_ignore_ascii_case("dialog") => FormMethod::Dialog,
                _ => FormMethod::Get,
            };
            (action, method)
        },
        _ => return None,
    };

    let mut controls = BTreeSet::new();
    // This deliberately describes descendant controls in the standards-built
    // DOM tree. Any specified `form=...` invokes explicit owner association
    // that this local descendant model cannot resolve, so it remains inert.
    let mut pending: Vec<Handle> = handle.children.borrow().iter().rev().cloned().collect();
    while let Some(child) = pending.pop() {
        if let NodeData::Element { name, attrs, .. } = &child.data {
            if name.ns == ns!(html)
                && matches!(
                    name.local.as_ref(),
                    "input" | "select" | "textarea" | "button"
                )
                && html_attribute(attrs, "form").is_none()
            {
                if let Some(control_name) = html_attribute(attrs, "name") {
                    if !control_name.is_empty() && control_name.len() <= MAX_DISCOVERY_NAME_BYTES {
                        bounded_insert(&mut controls, control_name, MAX_CONTROLS_PER_FORM);
                    }
                }
            }
        }
        pending.extend(child.children.borrow().iter().rev().cloned());
    }

    Some(DiscoveredForm {
        action: canonicalize_url(action),
        method,
        controls: controls.into_iter().collect(),
    })
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
    use std::{
        net::SocketAddr,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    use super::*;
    use crate::legacy_discovery::DiscoveryLimits;

    struct FixtureResponse {
        status: &'static str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl FixtureResponse {
        fn html(body: impl Into<String>) -> Self {
            Self::media("text/html", body)
        }

        fn media(content_type: &str, body: impl Into<String>) -> Self {
            Self {
                status: "200 OK",
                headers: vec![("Content-Type".to_owned(), content_type.to_owned())],
                body: body.into().into_bytes(),
            }
        }

        fn redirect(location: impl Into<String>) -> Self {
            Self {
                status: "302 Found",
                headers: vec![
                    ("Content-Type".to_owned(), "text/html".to_owned()),
                    ("Location".to_owned(), location.into()),
                ],
                body: Vec::new(),
            }
        }
    }

    struct LocalFixture {
        target: Url,
        requests: Arc<Mutex<Vec<String>>>,
        task: JoinHandle<()>,
    }

    impl LocalFixture {
        fn request_paths(&self) -> Vec<String> {
            self.requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    impl Drop for LocalFixture {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    async fn serve_fixture(
        max_requests: usize,
        handler: impl Fn(&str, SocketAddr) -> FixtureResponse + Send + Sync + 'static,
    ) -> LocalFixture {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let observed_requests = Arc::clone(&requests);
        let handler = Arc::new(handler);
        let task = tokio::spawn(async move {
            for _ in 0..max_requests {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0_u8; 1_024];
                    let read = stream.read(&mut chunk).await.unwrap();
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..read]);
                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                    assert!(request.len() <= 16 * 1_024, "fixture request too large");
                }
                let target = String::from_utf8_lossy(&request)
                    .lines()
                    .next()
                    .and_then(|line| line.split_ascii_whitespace().nth(1))
                    .unwrap()
                    .to_owned();
                observed_requests
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(target.clone());
                let response = handler(&target, address);
                let mut head = format!(
                    "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                    response.status,
                    response.body.len()
                );
                for (name, value) in response.headers {
                    head.push_str(&format!("{name}: {value}\r\n"));
                }
                head.push_str("\r\n");
                if stream.write_all(head.as_bytes()).await.is_ok() {
                    let _ = stream.write_all(&response.body).await;
                }
                let _ = stream.shutdown().await;
            }
        });

        LocalFixture {
            target: Url::parse(&format!("http://{address}/")).unwrap(),
            requests,
            task,
        }
    }

    fn discovery_limits(
        max_depth: usize,
        max_pages: usize,
        max_requests: u32,
        max_response_body_bytes: usize,
    ) -> DiscoveryLimits {
        let limits = DiscoveryLimits::new()
            .with_max_depth(max_depth)
            .with_max_requests(max_requests);
        let limits = limits.with_max_pages(max_pages).unwrap();
        let limits = limits.with_request_timeout(Duration::from_secs(2)).unwrap();
        let limits = limits.with_max_wall_time(Duration::from_secs(10)).unwrap();
        limits
            .with_body_limits(1024 * 1024, max_response_body_bytes)
            .unwrap()
    }

    fn scan_context(target: Url, limits: DiscoveryLimits) -> ScanContext {
        let (telemetry, _receiver) = tokio::sync::mpsc::unbounded_channel();
        ScanContext::new_with_discovery_limits(target, reqwest::Client::new(), telemetry, limits)
    }

    #[test]
    fn phase_identity_is_stable() {
        let crawl = CrawlPhase;
        assert_eq!(crawl.phase_number(), 2);
        assert_eq!(crawl.name(), "Web Crawler & Parameter Discovery");
    }

    #[test]
    fn crawler_scope_requires_the_exact_normalized_origin() {
        let target = Url::parse("https://example.test/app").unwrap();

        assert!(same_origin(
            &target,
            &Url::parse("https://example.test/next").unwrap()
        ));
        assert!(same_origin(
            &target,
            &Url::parse("https://example.test:443/explicit-default").unwrap()
        ));
        assert!(!same_origin(
            &target,
            &Url::parse("http://example.test/downgrade").unwrap()
        ));
        assert!(!same_origin(
            &target,
            &Url::parse("https://example.test:8443/other-service").unwrap()
        ));
        assert!(!same_origin(
            &target,
            &Url::parse("https://other.test/outside").unwrap()
        ));
    }

    #[test]
    fn canonicalization_drops_fragments_default_ports_and_sorts_unique_queries() {
        let first = canonicalize_url(
            Url::parse("https://EXAMPLE.test:443/a/../page?z=last&a=first#section").unwrap(),
        );
        let second =
            canonicalize_url(Url::parse("https://example.test/page?a=first&z=last#other").unwrap());
        assert_eq!(first, second);
        assert_eq!(first.as_str(), "https://example.test/page?a=first&z=last");
    }

    #[test]
    fn canonicalization_preserves_repeated_query_name_order() {
        let url = canonicalize_url(
            Url::parse("https://example.test/?choice=first&choice=second&a=1").unwrap(),
        );
        assert_eq!(
            url.query(),
            Some("choice=first&choice=second&a=1"),
            "repeated-value application semantics must not be reordered"
        );
    }

    #[test]
    fn resolution_handles_relative_root_and_absolute_references() {
        let origin = Url::parse("https://example.test/app/index.html").unwrap();
        assert_eq!(
            resolve_same_origin(&origin, "next", &origin)
                .unwrap()
                .as_str(),
            "https://example.test/app/next"
        );
        assert_eq!(
            resolve_same_origin(&origin, "/root", &origin)
                .unwrap()
                .as_str(),
            "https://example.test/root"
        );
        assert_eq!(
            resolve_same_origin(
                &origin,
                "https://example.test/absolute?b=2&a=1#fragment",
                &origin,
            )
            .unwrap()
            .as_str(),
            "https://example.test/absolute?a=1&b=2"
        );
        assert!(resolve_same_origin(&origin, "https://outside.test/", &origin).is_none());
        assert!(resolve_same_origin(&origin, "javascript:alert(1)", &origin).is_none());
        assert!(
            resolve_same_origin(&origin, "https://user:secret@example.test/private", &origin)
                .is_none()
        );
    }

    #[test]
    fn supported_media_type_is_explicit_and_parameter_tolerant() {
        assert!(supported_html_media_type("text/html; charset=utf-8"));
        assert!(supported_html_media_type("TEXT/HTML"));
        assert!(!supported_html_media_type("application/xhtml+xml"));
        assert!(!supported_html_media_type("text/plain"));
        assert!(!supported_html_media_type("application/json"));
        assert!(!supported_html_media_type(""));
    }

    #[test]
    fn standards_parser_extracts_links_and_typed_forms() {
        let document_url = Url::parse("https://example.test/app/page?existing=1").unwrap();
        let document = br#"
            <!doctype html>
            <base href="/base/">
            <a href="relative?z=2&a=1#part">relative</a>
            <a href="/root">root</a>
            <script>"<a href='/not-a-link'>"</script>
            <form action="submit?kept=yes" method="GET">
              <input name="query"><select name="kind"></select>
              <textarea name="notes"></textarea><button name="commit"></button>
            </form>
            <form action="/write" method="PoSt">
              <input name="csrf"><button name="save"></button>
            </form>
            <form method="dialog"><input name="choice"></form>
        "#;
        let parsed = parse_html_document(&document_url, document);

        assert_eq!(
            parsed.links,
            vec![
                Url::parse("https://example.test/base/relative?a=1&z=2").unwrap(),
                Url::parse("https://example.test/root").unwrap(),
            ]
        );
        assert_eq!(parsed.forms.len(), 3);
        let get = parsed
            .forms
            .iter()
            .find(|form| form.method == FormMethod::Get)
            .unwrap();
        let post = parsed
            .forms
            .iter()
            .find(|form| form.method == FormMethod::Post)
            .unwrap();
        let dialog = parsed
            .forms
            .iter()
            .find(|form| form.method == FormMethod::Dialog)
            .unwrap();
        assert_eq!(
            get.action.as_str(),
            "https://example.test/base/submit?kept=yes"
        );
        assert_eq!(get.controls, vec!["commit", "kind", "notes", "query"]);
        assert_eq!(post.action.as_str(), "https://example.test/write");
        assert_eq!(post.controls, vec!["csrf", "save"]);
        assert_eq!(dialog.action, document_url);
    }

    #[test]
    fn missing_or_empty_form_action_targets_the_document_not_base_element() {
        let document_url = Url::parse("https://example.test/current?kept=1").unwrap();
        let parsed = parse_html_document(
            &document_url,
            br#"<base href="/elsewhere/"><form><input name="a"></form><form action=""><input name="b"></form>"#,
        );
        assert_eq!(parsed.forms.len(), 2);
        assert!(parsed.forms.iter().all(|form| form.action == document_url));
    }

    #[test]
    fn invalid_first_base_href_is_not_rescued_by_later_base() {
        let document_url = Url::parse("https://example.test/document").unwrap();
        let parsed = parse_html_document(
            &document_url,
            br#"<base href="http://[invalid"><base href="/first/"><base href="/second/"><a href="next">next</a>"#,
        );
        assert_eq!(
            parsed.links,
            vec![Url::parse("https://example.test/next").unwrap()]
        );
    }

    #[test]
    fn non_http_first_base_falls_back_and_is_not_rescued() {
        let document_url = Url::parse("https://example.test/path/document").unwrap();
        let parsed = parse_html_document(
            &document_url,
            br#"<base href="javascript:alert(1)"><base href="/rescue/"><a href="next">next</a>"#,
        );
        assert_eq!(
            parsed.links,
            vec![Url::parse("https://example.test/path/next").unwrap()]
        );
    }

    #[test]
    fn cross_origin_http_base_resolves_before_scope_filtering() {
        let document_url = Url::parse("https://example.test/document").unwrap();
        let parsed = parse_html_document(
            &document_url,
            br#"<base href="https://outside.test/base/"><a href="next">next</a>"#,
        );
        assert_eq!(
            parsed.links,
            vec![Url::parse("https://outside.test/base/next").unwrap()]
        );
        assert!(
            resolve_same_origin(&document_url, parsed.links[0].as_str(), &document_url).is_none()
        );
    }

    #[test]
    fn first_parseable_base_wins_over_later_base() {
        let document_url = Url::parse("https://example.test/document").unwrap();
        let parsed = parse_html_document(
            &document_url,
            br#"<base href="/first/"><base href="/second/"><a href="next">next</a>"#,
        );
        assert_eq!(
            parsed.links,
            vec![Url::parse("https://example.test/first/next").unwrap()]
        );
    }

    #[test]
    fn invalid_method_uses_html_get_default() {
        let document_url = Url::parse("https://example.test/document").unwrap();
        let parsed = parse_html_document(
            &document_url,
            br#"<form method="delete" action="/resource"><input name="id"></form>"#,
        );
        assert_eq!(parsed.forms[0].method, FormMethod::Get);
    }

    #[test]
    fn invalid_present_form_action_is_inert_instead_of_falling_back() {
        let document_url = Url::parse("https://example.test/document").unwrap();
        let parsed = parse_html_document(
            &document_url,
            br#"
                <form action="http://[invalid"><input name="invalid"></form>
                <form action="javascript:alert(1)"><input name="non-http"></form>
                <form><input name="kept"></form>
            "#,
        );

        assert_eq!(parsed.forms.len(), 1);
        assert_eq!(parsed.forms[0].action, document_url);
        assert_eq!(parsed.forms[0].controls, vec!["kept"]);
    }

    #[test]
    fn explicit_nonempty_form_owner_is_not_attributed_to_descendant_form() {
        let document_url = Url::parse("https://example.test/document").unwrap();
        let parsed = parse_html_document(
            &document_url,
            br#"
                <form id="local">
                  <input name="kept">
                  <input name="other" form="elsewhere">
                  <input name="empty-owner" form="">
                  <input name="whitespace-owner" form="   ">
                </form>
            "#,
        );

        assert_eq!(parsed.forms.len(), 1);
        assert_eq!(parsed.forms[0].controls, vec!["kept"]);
    }

    #[test]
    fn get_form_preserves_action_query_and_control_names() {
        let mut discovery = CrawlDiscovery::default();
        let form = DiscoveredForm {
            action: canonicalize_url(Url::parse("https://example.test/search?scope=docs").unwrap()),
            method: FormMethod::Get,
            controls: vec!["q".to_string(), "scope".to_string()],
        };
        discovery.register_get_form(&form);
        assert_eq!(
            discovery.endpoints[form.action.as_str()],
            BTreeSet::from(["q".to_string(), "scope".to_string()])
        );
    }

    #[test]
    fn post_form_remains_typed_and_is_not_registered_as_get_endpoint() {
        let mut discovery = CrawlDiscovery::default();
        let form = DiscoveredForm {
            action: Url::parse("https://example.test/write").unwrap(),
            method: FormMethod::Post,
            controls: vec!["body".to_string()],
        };
        discovery.forms.insert(form.clone());
        assert_eq!(discovery.forms, BTreeSet::from([form]));
        assert!(discovery.endpoints.is_empty());
    }

    #[test]
    fn root_endpoint_registration_includes_existing_query_names() {
        let root = canonicalize_url(
            Url::parse("https://example.test/start?mode=safe&token=redacted").unwrap(),
        );
        let mut discovery = CrawlDiscovery::default();
        discovery.register_endpoint(&root);
        assert_eq!(
            discovery.endpoints[root.as_str()],
            BTreeSet::from(["mode".to_string(), "token".to_string()])
        );
    }

    #[test]
    fn crawl_policy_is_explicit_and_finite() {
        let policy = CrawlPolicy {
            max_depth: 4,
            max_pages: 64,
        };
        assert_eq!(policy.max_depth, 4);
        assert_eq!(policy.max_pages, 64);
        assert_eq!(MAX_CRAWLER_HTML_PARSE_BYTES, 64 * 1024);
        assert!(policy.max_depth < policy.max_pages);
    }

    #[test]
    fn queue_model_is_breadth_first_and_depth_bounded() {
        let mut queue = VecDeque::from([
            (Url::parse("https://example.test/root").unwrap(), 0_usize),
            (Url::parse("https://example.test/second").unwrap(), 1_usize),
        ]);
        queue.push_back((Url::parse("https://example.test/third").unwrap(), 1_usize));
        assert_eq!(queue.pop_front().unwrap().0.path(), "/root");
        assert_eq!(queue.pop_front().unwrap().0.path(), "/second");
        assert_eq!(queue.pop_front().unwrap().0.path(), "/third");
    }

    #[test]
    fn canonical_sort_makes_budget_selection_independent_of_markup_order() {
        fn selected(markup: &[u8]) -> Vec<String> {
            let root = Url::parse("https://example.test/").unwrap();
            let mut candidates: Vec<_> = parse_html_document(&root, markup)
                .links
                .into_iter()
                .map(canonicalize_url)
                .collect();
            candidates.sort_by(|left, right| left.as_str().cmp(right.as_str()));
            candidates.into_iter().take(2).map(Into::into).collect()
        }

        assert_eq!(
            selected(br#"<a href="/c"></a><a href="/a"></a><a href="/b"></a>"#),
            selected(br#"<a href="/b"></a><a href="/c"></a><a href="/a"></a>"#)
        );
    }

    #[test]
    fn link_cap_keeps_the_same_lexicographically_smallest_urls_in_any_dom_order() {
        fn markup(indices: &[usize]) -> String {
            indices
                .iter()
                .map(|index| format!(r#"<a href="/link-{index:04}"></a>"#))
                .collect()
        }

        let document_url = Url::parse("https://example.test/").unwrap();
        let forward = (0..MAX_REFERENCES_PER_PAGE + 17).collect::<Vec<_>>();
        let reverse = forward.iter().copied().rev().collect::<Vec<_>>();
        let first = parse_html_document(&document_url, markup(&forward).as_bytes()).links;
        let second = parse_html_document(&document_url, markup(&reverse).as_bytes()).links;

        assert_eq!(first, second);
        assert_eq!(first.len(), MAX_REFERENCES_PER_PAGE);
        assert_eq!(first.first().unwrap().path(), "/link-0000");
        assert_eq!(
            first.last().unwrap().path(),
            format!("/link-{:04}", MAX_REFERENCES_PER_PAGE - 1)
        );
    }

    #[test]
    fn form_cap_keeps_the_same_lexicographically_smallest_forms_in_any_dom_order() {
        fn markup(indices: &[usize]) -> String {
            indices
                .iter()
                .map(|index| format!(r#"<form action="/form-{index:04}"><input name="q"></form>"#))
                .collect()
        }

        let document_url = Url::parse("https://example.test/").unwrap();
        let forward = (0..MAX_FORMS_PER_PAGE + 17).collect::<Vec<_>>();
        let reverse = forward.iter().copied().rev().collect::<Vec<_>>();
        let first = parse_html_document(&document_url, markup(&forward).as_bytes()).forms;
        let second = parse_html_document(&document_url, markup(&reverse).as_bytes()).forms;

        assert_eq!(first, second);
        assert_eq!(first.len(), MAX_FORMS_PER_PAGE);
        assert_eq!(first.first().unwrap().action.path(), "/form-0000");
        assert_eq!(
            first.last().unwrap().action.path(),
            format!("/form-{:04}", MAX_FORMS_PER_PAGE - 1)
        );
    }

    #[test]
    fn control_cap_keeps_the_same_lexicographically_smallest_names_in_any_dom_order() {
        fn markup(indices: &[usize]) -> String {
            let controls = indices
                .iter()
                .map(|index| format!(r#"<input name="control-{index:04}">"#))
                .collect::<String>();
            format!(r#"<form action="/submit">{controls}</form>"#)
        }

        let document_url = Url::parse("https://example.test/").unwrap();
        let forward = (0..MAX_CONTROLS_PER_FORM + 17).collect::<Vec<_>>();
        let reverse = forward.iter().copied().rev().collect::<Vec<_>>();
        let first = parse_html_document(&document_url, markup(&forward).as_bytes()).forms;
        let second = parse_html_document(&document_url, markup(&reverse).as_bytes()).forms;

        assert_eq!(first, second);
        assert_eq!(first[0].controls.len(), MAX_CONTROLS_PER_FORM);
        assert_eq!(first[0].controls.first().unwrap(), "control-0000");
        assert_eq!(
            first[0].controls.last().unwrap(),
            &format!("control-{:04}", MAX_CONTROLS_PER_FORM - 1)
        );
    }

    #[tokio::test]
    async fn depth_zero_registers_only_the_root_but_retains_passive_forms() {
        let fixture = serve_fixture(1, |target, _address| {
            assert_eq!(target, "/");
            FixtureResponse::html(
                r#"
                    <a href="/child">child</a>
                    <form action="/search" method="get"><input name="q"></form>
                    <form action="/write" method="post"><input name="body"></form>
                "#,
            )
        })
        .await;
        let context = scan_context(fixture.target.clone(), discovery_limits(0, 8, 8, 64 * 1024));

        CrawlPhase.execute(&context).await.unwrap();

        assert_eq!(fixture.request_paths(), vec!["/"]);
        let snapshot = context.discovery_snapshot();
        assert_eq!(snapshot.endpoints().len(), 1);
        assert!(snapshot.endpoints().contains_key(fixture.target.as_str()));
        assert!(snapshot
            .endpoints()
            .keys()
            .all(|url| !url.ends_with("/child") && !url.ends_with("/search")));
        assert_eq!(context.discovery_forms().len(), 2);
    }

    #[tokio::test]
    async fn one_page_budget_registers_only_the_root() {
        let fixture = serve_fixture(1, |target, _address| {
            assert_eq!(target, "/");
            FixtureResponse::html(r#"<a href="/a">a</a><a href="/b">b</a>"#)
        })
        .await;
        let context = scan_context(fixture.target.clone(), discovery_limits(8, 1, 8, 64 * 1024));

        CrawlPhase.execute(&context).await.unwrap();

        assert_eq!(fixture.request_paths(), vec!["/"]);
        let snapshot = context.discovery_snapshot();
        assert_eq!(snapshot.endpoints().len(), 1);
        assert!(snapshot.endpoints().contains_key(fixture.target.as_str()));
    }

    #[tokio::test]
    async fn page_budget_selects_canonical_candidates_before_registration() {
        let fixture = serve_fixture(2, |target, _address| match target {
            "/" => FixtureResponse::html(r#"<a href="/b">b</a><a href="/a">a</a>"#),
            "/a" => FixtureResponse::html(r#"<a href="/deep">deep</a>"#),
            other => panic!("unexpected crawler request: {other}"),
        })
        .await;
        let context = scan_context(fixture.target.clone(), discovery_limits(8, 2, 8, 64 * 1024));

        CrawlPhase.execute(&context).await.unwrap();

        assert_eq!(fixture.request_paths(), vec!["/", "/a"]);
        let endpoints = context.discovery_snapshot().endpoints().clone();
        assert_eq!(endpoints.len(), 2);
        assert!(endpoints.keys().any(|url| url.ends_with("/a")));
        assert!(endpoints
            .keys()
            .all(|url| !url.ends_with("/b") && !url.ends_with("/deep")));
    }

    #[tokio::test]
    async fn depth_budget_excludes_descendants_beyond_the_selected_frontier() {
        let fixture = serve_fixture(2, |target, _address| match target {
            "/" => FixtureResponse::html(r#"<a href="/child">child</a>"#),
            "/child" => FixtureResponse::html(r#"<a href="/deep">deep</a>"#),
            other => panic!("unexpected crawler request: {other}"),
        })
        .await;
        let context = scan_context(fixture.target.clone(), discovery_limits(1, 8, 8, 64 * 1024));

        CrawlPhase.execute(&context).await.unwrap();

        assert_eq!(fixture.request_paths(), vec!["/", "/child"]);
        let endpoints = context.discovery_snapshot().endpoints().clone();
        assert_eq!(endpoints.len(), 2);
        assert!(endpoints.keys().any(|url| url.ends_with("/child")));
        assert!(endpoints.keys().all(|url| !url.ends_with("/deep")));
    }

    #[tokio::test]
    async fn previsited_root_suppresses_the_root_request() {
        let fixture = serve_fixture(1, |_target, _address| {
            panic!("previsited root must not be requested")
        })
        .await;
        let context = scan_context(fixture.target.clone(), discovery_limits(1, 8, 8, 64 * 1024));
        context.mark_visited(fixture.target.to_string());

        CrawlPhase.execute(&context).await.unwrap();

        assert!(fixture.request_paths().is_empty());
        assert!(context
            .discovery_snapshot()
            .endpoints()
            .contains_key(fixture.target.as_str()));
    }

    #[tokio::test]
    async fn previsited_child_is_registered_but_not_requested_again() {
        let fixture = serve_fixture(1, |target, _address| {
            assert_eq!(target, "/");
            FixtureResponse::html(r#"<a href="/child">child</a>"#)
        })
        .await;
        let child = fixture.target.join("/child").unwrap();
        let context = scan_context(fixture.target.clone(), discovery_limits(1, 8, 8, 64 * 1024));
        context.mark_visited(child.to_string());

        CrawlPhase.execute(&context).await.unwrap();

        assert_eq!(fixture.request_paths(), vec!["/"]);
        let snapshot = context.discovery_snapshot();
        assert!(snapshot.endpoints().contains_key(child.as_str()));
        assert!(snapshot.visited().contains(child.as_str()));
        assert!(snapshot.visited().contains(fixture.target.as_str()));
    }

    #[tokio::test]
    async fn broker_crawl_is_same_origin_and_retains_typed_forms_without_post_probe() {
        let outside = serve_fixture(1, |_target, _address| {
            FixtureResponse::html("outside must not be requested")
        })
        .await;
        let outside_url = outside.target.to_string();
        let fixture = serve_fixture(6, move |target, address| match target {
            "/" => FixtureResponse::html(format!(
                r#"
                    <a href="relative">relative</a>
                    <a href="/root">root</a>
                    <a href="http://{address}/absolute">absolute</a>
                    <a href="{outside_url}outside">outside</a>
                    <a href="http://user:secret@{address}/private">credentials</a>
                    <a href="/redirect">redirect</a>
                    <form action="/search?existing=1" method="get">
                      <input name="q"><select name="kind"></select>
                    </form>
                    <form action="/write" method="post">
                      <textarea name="body"></textarea><button name="save"></button>
                    </form>
                "#
            )),
            "/redirect" => FixtureResponse::redirect(outside_url.clone()),
            "/absolute" | "/relative" | "/root" | "/search?existing=1" => FixtureResponse::html(""),
            other => panic!("unexpected crawler request: {other}"),
        })
        .await;
        let context = scan_context(fixture.target.clone(), discovery_limits(1, 8, 8, 64 * 1024));

        CrawlPhase.execute(&context).await.unwrap();

        assert_eq!(
            fixture.request_paths(),
            vec![
                "/",
                "/absolute",
                "/redirect",
                "/relative",
                "/root",
                "/search?existing=1",
            ]
        );
        assert!(outside.request_paths().is_empty());
        let snapshot = context.discovery_snapshot();
        assert_eq!(snapshot.endpoints().len(), 6);
        assert!(snapshot
            .endpoints()
            .keys()
            .all(|url| !url.contains("outside") && !url.contains("@") && !url.ends_with("/write")));
        let search = snapshot
            .endpoints()
            .iter()
            .find(|(url, _)| url.ends_with("/search?existing=1"))
            .unwrap()
            .1;
        assert_eq!(
            search,
            &BTreeSet::from(["existing".to_owned(), "kind".to_owned(), "q".to_owned()])
        );
        let forms = context.discovery_forms();
        assert_eq!(forms.len(), 2);
        let post = forms
            .iter()
            .find(|form| form.method() == DiscoveryFormMethod::Post)
            .unwrap();
        assert!(post.action().as_str().ends_with("/write"));
        assert_eq!(
            post.controls(),
            &BTreeSet::from(["body".to_owned(), "save".to_owned()])
        );
    }

    #[tokio::test]
    async fn broker_crawl_requests_each_canonical_url_exactly_once() {
        let fixture = serve_fixture(2, |target, address| match target {
            "/" => FixtureResponse::html(format!(
                r#"
                    <a href="/page?b=2&a=1#one">first</a>
                    <a href="/page?a=1&b=2#two">second</a>
                    <a href="http://{address}/page?a=1&b=2">third</a>
                "#
            )),
            "/page?a=1&b=2" => FixtureResponse::html(""),
            other => panic!("unexpected crawler request: {other}"),
        })
        .await;
        let context = scan_context(fixture.target.clone(), discovery_limits(1, 8, 8, 64 * 1024));

        CrawlPhase.execute(&context).await.unwrap();

        assert_eq!(fixture.request_paths(), vec!["/", "/page?a=1&b=2"]);
        assert_eq!(context.discovery_snapshot().endpoints().len(), 2);
    }

    #[tokio::test]
    async fn truncated_html_is_not_partially_parsed() {
        let fixture = serve_fixture(1, |target, _address| {
            assert_eq!(target, "/");
            FixtureResponse::html(format!(
                "<a href=\"/must-not-be-observed\">link</a>{}",
                "x".repeat(8 * 1024)
            ))
        })
        .await;
        let context = scan_context(fixture.target.clone(), discovery_limits(1, 8, 8, 64));

        CrawlPhase.execute(&context).await.unwrap();

        let snapshot = context.discovery_snapshot();
        assert_eq!(fixture.request_paths(), vec!["/"]);
        assert_eq!(snapshot.endpoints().len(), 1, "partial HTML must be inert");
        assert!(snapshot
            .endpoints()
            .keys()
            .all(|url| !url.contains("must-not-be-observed")));
    }

    #[tokio::test]
    async fn complete_body_over_hard_html_parse_cap_is_inert() {
        let fixture = serve_fixture(1, |target, _address| {
            assert_eq!(target, "/");
            let prefix = r#"<a href="/must-not-be-observed">link</a>"#;
            FixtureResponse::html(format!(
                "{prefix}{}",
                "x".repeat(MAX_CRAWLER_HTML_PARSE_BYTES + 1 - prefix.len())
            ))
        })
        .await;
        let context = scan_context(
            fixture.target.clone(),
            discovery_limits(1, 8, 8, MAX_CRAWLER_HTML_PARSE_BYTES * 2),
        );

        CrawlPhase.execute(&context).await.unwrap();

        let snapshot = context.discovery_snapshot();
        assert_eq!(fixture.request_paths(), vec!["/"]);
        assert_eq!(snapshot.endpoints().len(), 1);
        assert!(snapshot
            .endpoints()
            .keys()
            .all(|url| !url.contains("must-not-be-observed")));
    }

    #[tokio::test]
    async fn exact_hard_html_parse_cap_remains_eligible() {
        let fixture = serve_fixture(2, |target, _address| match target {
            "/" => {
                let prefix = r#"<a href="/at-boundary">link</a>"#;
                FixtureResponse::html(format!(
                    "{prefix}{}",
                    "x".repeat(MAX_CRAWLER_HTML_PARSE_BYTES - prefix.len())
                ))
            },
            "/at-boundary" => FixtureResponse::html(""),
            other => panic!("unexpected crawler request: {other}"),
        })
        .await;
        let context = scan_context(
            fixture.target.clone(),
            discovery_limits(1, 8, 8, MAX_CRAWLER_HTML_PARSE_BYTES * 2),
        );

        CrawlPhase.execute(&context).await.unwrap();

        assert_eq!(fixture.request_paths(), vec!["/", "/at-boundary"]);
        assert!(context
            .discovery_snapshot()
            .endpoints()
            .contains_key(fixture.target.join("/at-boundary").unwrap().as_str()));
    }

    #[tokio::test]
    async fn mid_crawl_budget_failure_commits_no_partial_state() {
        let fixture = serve_fixture(1, |target, _address| {
            assert_eq!(target, "/");
            FixtureResponse::html(r#"<a href="/second">second</a>"#)
        })
        .await;
        let context = scan_context(fixture.target.clone(), discovery_limits(1, 8, 1, 64 * 1024));
        let before = context.discovery_snapshot();

        let error = CrawlPhase.execute(&context).await.unwrap_err();

        assert!(matches!(error, ScannerError::BudgetExceeded(_)));
        assert_eq!(fixture.request_paths(), vec!["/"]);
        assert_eq!(context.discovery_snapshot(), before);
        assert_eq!(context.discovered_endpoints.len(), 1);
        assert!(context
            .discovered_endpoints
            .contains_key(fixture.target.as_str()));
        assert!(context.visited_urls.is_empty());
        assert!(context.discovery_forms().is_empty());
    }
}
