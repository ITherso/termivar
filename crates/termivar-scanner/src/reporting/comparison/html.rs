//! Standalone, display-only comparison screen. Imported values never become code.

use super::super::{write_html_text, RenderBuffer, ReportError};
use super::{ComparisonDocument, ComparisonError, ComparisonItem, ItemProjection, SourceMetadata};
use base64::{engine::general_purpose::STANDARD, Engine};
use sha2::{Digest, Sha256};

const STYLE: &str = r#":root{color-scheme:light dark;--bg:#f4f6fa;--panel:#fff;--ink:#172235;--muted:#526178;--line:#d8e0eb;--accent:#315ec9;--soft:#eaf0ff;--after:#176b70;--before:#79542c;--changed:#714db3;--same:#526178}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{max-width:1120px;margin:auto;padding:40px 24px 60px}h1{font-size:clamp(1.9rem,5vw,2.7rem);line-height:1.15;margin:8px 0 14px;letter-spacing:-.035em}h2{font-size:1.15rem;margin:0}h3{font-size:1rem;margin:0}.eyebrow{letter-spacing:.14em;font-size:.72rem;font-weight:750;color:var(--accent);text-transform:uppercase}.muted{color:var(--muted)}.intro{max-width:780px}.notice{border-left:3px solid var(--accent);padding:12px 16px;background:var(--soft);margin:22px 0}.sources{display:grid;grid-template-columns:1fr 1fr;gap:16px}.source,.card,.item{background:var(--panel);border:1px solid var(--line);border-radius:12px}.source{padding:16px}.source h2{margin-bottom:6px}.hash{font:12px/1.6 ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere}.source dl{font-size:.82rem;margin:8px 0 0}.source dt{font-weight:650}.source dd{margin:0 0 6px;overflow-wrap:anywhere}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:24px 0 12px}.card{padding:16px;border-top:3px solid var(--same)}.card.after{border-top-color:var(--after)}.card.before{border-top-color:var(--before)}.card.changed{border-top-color:var(--changed)}.number{font-size:2rem;line-height:1.15;display:block;font-weight:730}.card p{margin:6px 0 0;font-size:.78rem;color:var(--muted)}.controls{position:sticky;top:0;z-index:1;background:var(--bg);padding:16px 0;border-bottom:1px solid var(--line)}label{display:block;font-weight:650;margin-bottom:6px}input{font:inherit;color:var(--ink);background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:10px 12px;width:100%}.filters{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}button{font:inherit;font-size:.85rem;padding:8px 12px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--ink);cursor:pointer}button[aria-pressed=true]{background:var(--accent);color:#fff;border-color:var(--accent)}:focus-visible{outline:3px solid var(--accent);outline-offset:3px}#visible-count{font-size:.85rem;margin:10px 0 0}.items{display:grid;gap:12px;margin-top:20px}.item{padding:18px;overflow-wrap:anywhere}.item-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}.badge{font-size:.72rem;font-weight:700;padding:4px 8px;border:1px solid var(--line);border-radius:6px;white-space:nowrap}.capability{font:12px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;color:var(--muted);margin:6px 0 12px}.summary{margin:0 0 10px;white-space:pre-wrap}.item details{margin-top:14px}.item summary{cursor:pointer;font-weight:650;min-height:30px}.identity{margin:10px 0;color:var(--muted);font-size:.78rem}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;table-layout:fixed;font-size:.85rem;margin-top:10px}th,td{text-align:left;vertical-align:top;padding:10px;border-bottom:1px solid var(--line);white-space:pre-wrap;overflow-wrap:anywhere}th:first-child{width:22%}thead{background:var(--soft)}tr.different>th::after{content:" · changed";display:block;font-size:.7rem;color:var(--accent)}.empty{padding:28px;text-align:center;border:1px dashed var(--line);border-radius:10px;margin-top:20px}.skip{position:absolute;left:-10000px}.skip:focus{left:16px;top:8px;z-index:3;background:var(--panel);padding:10px}footer{margin-top:30px;border-top:1px solid var(--line);padding-top:16px;font-size:.8rem;color:var(--muted)}[hidden]{display:none!important}@media(prefers-color-scheme:dark){:root{--bg:#111820;--panel:#192330;--ink:#edf2fa;--muted:#b1bdd0;--line:#36455b;--accent:#9bb8ff;--soft:#202e46;--after:#66c1bc;--before:#d4ae7d;--changed:#b7a0e2;--same:#9cacc2}button[aria-pressed=true]{color:#152239}}@media(max-width:620px){main{padding:24px 14px}.sources{grid-template-columns:1fr}.cards{grid-template-columns:1fr 1fr}.item-heading{display:block}.badge{display:inline-block;margin-top:8px}.item{padding:14px}th,td{padding:8px}th:first-child{width:25%}.controls{position:static}}@media print{:root{color-scheme:light;--bg:#fff;--panel:#fff;--ink:#000;--muted:#333;--line:#bbb;--soft:#f0f0f0;--accent:#333}main{max-width:none;padding:0}body{font-size:10pt}.controls,.skip,noscript,#empty-filter{display:none!important}.item[hidden]{display:block!important}.item{break-inside:avoid;border-radius:0;margin-bottom:12px}.items{display:block}details::details-content{content-visibility:visible}details:not([open])>*:not(summary){display:block!important}.table-wrap{overflow:visible}summary{list-style:none}.sources,.cards{break-inside:avoid}.notice{margin:12px 0}footer{font-size:8pt}}"#;

// This exact program is hashed into CSP; no report data is interpolated here.
const SCRIPT: &str = r#"(()=>{'use strict';const controls=document.getElementById('controls');const search=document.getElementById('search');const buttons=Array.from(document.querySelectorAll('[data-filter]'));const items=Array.from(document.querySelectorAll('article[data-group]'));const status=document.getElementById('visible-count');const empty=document.getElementById('empty-filter');let group='all';const apply=()=>{const query=search.value.toLocaleLowerCase('en-US').trim();let count=0;for(const item of items){const matches=(group==='all'||item.dataset.group===group)&&item.textContent.toLocaleLowerCase('en-US').includes(query);item.hidden=!matches;if(matches)count++;}status.textContent=count+' of '+items.length+' observations shown';empty.hidden=count!==0;};search.addEventListener('input',apply);for(const button of buttons){button.addEventListener('click',()=>{group=button.dataset.filter;for(const other of buttons)other.setAttribute('aria-pressed',String(other===button));apply();});}let opened=[];window.addEventListener('beforeprint',()=>{opened=Array.from(document.querySelectorAll('details')).map(detail=>[detail,detail.open]);for(const [detail]of opened)detail.open=true;});window.addEventListener('afterprint',()=>{for(const [detail,wasOpen]of opened)detail.open=wasOpen;opened=[];});controls.hidden=false;apply();})();"#;

pub(super) fn render(
    document: &ComparisonDocument,
    limit: usize,
) -> Result<String, ComparisonError> {
    let mut output = RenderBuffer::new(limit);
    let script_hash = STANDARD.encode(Sha256::digest(SCRIPT.as_bytes()));
    let style_hash = STANDARD.encode(Sha256::digest(STYLE.as_bytes()));
    output.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; base-uri 'none'; connect-src 'none'; form-action 'none'; frame-src 'none'; object-src 'none'; script-src 'sha256-")?;
    output.push_str(&script_hash)?;
    output.push_str("'; style-src 'sha256-")?;
    output.push_str(&style_hash)?;
    output.push_str("'\"><title>Termivar — Report comparison</title><style>")?;
    output.push_str(STYLE)?;
    output.push_str("</style></head><body><a class=\"skip\" href=\"#observations\">Skip to observations</a><main><header><div class=\"eyebrow\">Termivar / Offline report compare</div><h1>Compare observations</h1><p class=\"intro muted\">A side-by-side view of two supplied assessment documents. No assessment was rerun.</p></header><p class=\"notice\"><strong>Disappearance is not verified remediation.</strong> Presence only in the after report does not establish when a condition appeared. Imported claims are displayed, not independently endorsed.</p><section class=\"sources\" aria-label=\"Supplied reports\">")?;
    source(&mut output, "Before report", &document.before)?;
    source(&mut output, "After report", &document.after)?;
    output.push_str("</section><p class=\"muted\">Scope assurance: operator-declared. Coverage equivalence: not established. Source authenticity: not established by parsing.</p><section class=\"cards\" aria-label=\"Comparison totals\">")?;
    let groups = [
        (
            "only_in_after",
            "Only in after",
            "after",
            &document.only_in_after,
        ),
        (
            "only_in_before",
            "Only in before",
            "before",
            &document.only_in_before,
        ),
        ("changed", "Changed", "changed", &document.changed),
        ("unchanged", "Unchanged", "same", &document.unchanged),
    ];
    let total = groups
        .iter()
        .map(|(_, _, _, items)| items.len())
        .sum::<usize>();
    for (_, label, class, items) in &groups {
        output.push_fmt(format_args!("<div class=\"card {class}\"><span class=\"number\">{}</span><h2>{label}</h2><p>{}</p></div>", items.len(), match *class {
            "after" => "Present only in the supplied after report",
            "before" => "Present only in the supplied before report",
            "changed" => "Matched identity, different comparable content",
            _ => "Matched identity and equal comparable content",
        }))?;
    }
    output.push_fmt(format_args!("</section><p class=\"muted\">{total} matched or one-sided observations in total. Reference renumbering is ignored.</p><section id=\"controls\" class=\"controls\" aria-label=\"Filter observations\" hidden><label for=\"search\">Search displayed observations</label><input id=\"search\" type=\"search\" autocomplete=\"off\" placeholder=\"Search titles, summaries, capabilities or field values\" aria-controls=\"observations\"><div class=\"filters\" role=\"group\" aria-label=\"Comparison group\"><button type=\"button\" data-filter=\"all\" aria-pressed=\"true\">All ({total})</button>"))?;
    for (key, label, _, items) in &groups {
        output.push_fmt(format_args!("<button type=\"button\" data-filter=\"{key}\" aria-pressed=\"false\">{label} ({})</button>", items.len()))?;
    }
    output.push_str("</div><p id=\"visible-count\" role=\"status\" aria-live=\"polite\"></p></section><noscript><p>Search and filters are unavailable. Every comparison item remains readable below; expand an item to see its fields.</p></noscript><p id=\"empty-filter\" class=\"empty\" hidden>No observations match this search and group. Clear the search or choose All.</p><section id=\"observations\" class=\"items\" aria-label=\"Compared observations\" tabindex=\"-1\">")?;
    for (key, label, _, items) in groups {
        for item in items {
            observation(&mut output, key, label, item)?;
        }
    }
    if total == 0 {
        output.push_str("<p class=\"empty\">Both supplied complete reports contain no observations. This is not a security verdict.</p>")?;
    }
    output.push_str("</section><footer><p>Only supported comparable fields are compared. Evidence metadata differences do not establish a better or worse security condition. Report-local subject, evidence, case and outcome labels are not authenticated target identities.</p><p>Imported text may contain sensitive information. Display encoding prevents active content; it does not remove secrets. Review this document before sharing. Printing includes all groups and field details.</p><p>Comparison schema: ")?;
    write_html_text(&mut output, document.schema)?;
    output.push_str("</p></footer></main><script>")?;
    output.push_str(SCRIPT)?;
    output.push_str("</script></body></html>")?;
    Ok(output.finish())
}

fn source(
    output: &mut RenderBuffer,
    label: &str,
    metadata: &SourceMetadata,
) -> Result<(), ReportError> {
    output.push_str("<div class=\"source\"><h2>")?;
    write_html_text(output, label)?;
    output.push_str("</h2><div class=\"hash\">SHA-256: ")?;
    write_html_text(output, &metadata.sha256)?;
    output.push_str("</div><dl>")?;
    for (name, value) in [
        ("Document schema", metadata.schema.as_str()),
        ("Source schema", metadata.source_schema.as_str()),
        ("Run schema", metadata.run_schema.as_str()),
        ("Profile schema", metadata.profile_schema.as_str()),
        ("Profile", metadata.profile.as_str()),
    ] {
        output.push_str("<dt>")?;
        write_html_text(output, name)?;
        output.push_str("</dt><dd>")?;
        write_html_text(output, value)?;
        output.push_str("</dd>")?;
    }
    output.push_fmt(format_args!(
        "<dt>Supplied counts</dt><dd>{} observations · {} subjects</dd></dl></div>",
        metadata.item_count, metadata.subject_count
    ))
}

fn observation(
    output: &mut RenderBuffer,
    group: &str,
    label: &str,
    item: &ComparisonItem,
) -> Result<(), ReportError> {
    let preview = item.after.as_ref().or(item.before.as_ref());
    output.push_str("<article class=\"item\" data-group=\"")?;
    write_html_text(output, group)?;
    output.push_str("\"><div class=\"item-heading\"><h3>")?;
    write_html_text(
        output,
        preview.map_or("Observation", |value| value.title.as_str()),
    )?;
    output.push_str("</h3><span class=\"badge\">")?;
    write_html_text(output, label)?;
    output.push_str("</span></div><p class=\"capability\">")?;
    write_html_text(output, &item.capability_id)?;
    output.push_str("</p><p class=\"summary\">")?;
    write_html_text(
        output,
        preview.map_or("", |value| value.redacted_summary.as_str()),
    )?;
    output.push_str("</p><details><summary>Before / after fields")?;
    if !item.changed_fields.is_empty() {
        output.push_str(" — changed: ")?;
        write_html_text(output, &item.changed_fields.join(", "))?;
    }
    output.push_str("</summary><p class=\"identity hash\">Matched identity: ")?;
    write_html_text(output, &item.fingerprint)?;
    output.push_str("</p><div class=\"table-wrap\"><table><caption>Comparable content as supplied</caption><thead><tr><th scope=\"col\">Field</th><th scope=\"col\">Before</th><th scope=\"col\">After</th></tr></thead><tbody>")?;
    let before = item.before.as_ref().map(fields);
    let after = item.after.as_ref().map(fields);
    for index in 0..FIELD_LABELS.len() {
        let left = before.as_ref().map(|values| values[index].as_str());
        let right = after.as_ref().map(|values| values[index].as_str());
        row(output, FIELD_LABELS[index], left, right)?;
    }
    output.push_str("</tbody></table></div><p class=\"muted\">Evidence metadata describes supplied linkage counts and stage, not reconstructed evidence or a security improvement.</p></details></article>")
}

const FIELD_LABELS: [&str; 13] = [
    "Title",
    "Category",
    "Imported disposition",
    "Imported claim basis",
    "Severity",
    "CWE",
    "Confidence (ppm)",
    "Summary",
    "Remediation ID",
    "Remediation",
    "Evidence / reference counts",
    "Case / outcome present",
    "Verification stage",
];

fn fields(item: &ItemProjection) -> [String; 13] {
    [
        item.title.clone(),
        item.category.clone(),
        item.disposition.clone(),
        item.claim_basis.clone(),
        item.severity
            .clone()
            .unwrap_or_else(|| "Not reported".to_owned()),
        item.cwe
            .clone()
            .unwrap_or_else(|| "Not reported".to_owned()),
        item.confidence_ppm.to_string(),
        item.redacted_summary.clone(),
        item.remediation.id.clone(),
        item.remediation.summary.clone(),
        format!(
            "Total: {}; general: {}; control: {}; candidate: {}",
            item.evidence.evidence_count,
            item.evidence.evidence_reference_count,
            item.evidence.control_reference_count,
            item.evidence.candidate_reference_count
        ),
        format!(
            "Case: {}; outcome: {}",
            item.evidence.case_present, item.evidence.outcome_present
        ),
        item.evidence
            .verification_stage
            .clone()
            .unwrap_or_else(|| "Not applicable".to_owned()),
    ]
}

fn row(
    output: &mut RenderBuffer,
    label: &str,
    before: Option<&str>,
    after: Option<&str>,
) -> Result<(), ReportError> {
    output.push_str(if before != after {
        "<tr class=\"different\"><th scope=\"row\">"
    } else {
        "<tr><th scope=\"row\">"
    })?;
    write_html_text(output, label)?;
    output.push_str("</th>")?;
    for value in [before, after] {
        output.push_str("<td>")?;
        write_html_text(
            output,
            value.unwrap_or("Not present in this supplied report"),
        )?;
        output.push_str("</td>")?;
    }
    output.push_str("</tr>")
}

#[cfg(test)]
mod tests {
    use super::super::{compare_documents, compare_reports, import, ComparisonFormat};
    use super::*;
    use serde_json::Value;

    const SAMPLE: &[u8] = include_bytes!("../../../../../docs/examples/first-use/assessment.json");

    fn variants() -> (Vec<u8>, Vec<u8>) {
        let mut before: Value = serde_json::from_slice(SAMPLE).unwrap();
        before["items"].as_array_mut().unwrap().truncate(3);
        before["item_count"] = 3.into();
        let mut after = before.clone();
        after["items"][0]["title"] = "Synthetic changed title".into();
        after["items"][0]["redacted_summary"] =
            "Synthetic comparison variant, not another scan.".into();
        after["items"][2]["fingerprint"] = format!("sha256:{}", "c".repeat(64)).into();
        (
            serde_json::to_vec(&before).unwrap(),
            serde_json::to_vec(&after).unwrap(),
        )
    }

    #[test]
    fn all_groups_fields_and_remediation_are_prerendered_without_script_dependence() {
        let (before, after) = variants();
        let rendered = compare_reports(&before, &after, ComparisonFormat::Html).unwrap();
        for group in ["only_in_after", "only_in_before", "changed", "unchanged"] {
            assert_eq!(
                rendered.matches(&format!("data-group=\"{group}\"")).count(),
                1
            );
        }
        assert_eq!(rendered.matches("<article ").count(), 4);
        assert_eq!(rendered.matches("<details>").count(), 4);
        assert!(!rendered.contains("<article hidden"));
        assert!(rendered.contains(
            "id=\"controls\" class=\"controls\" aria-label=\"Filter observations\" hidden"
        ));
        assert!(rendered.contains("<noscript>"));
        assert!(rendered.contains("Synthetic changed title"));
        assert!(rendered.contains("Define and validate a Content-Security-Policy"));
        assert!(rendered.contains("Not present in this supplied report"));
        assert!(rendered.contains("Case: false; outcome: false"));
        assert!(rendered.contains("Not applicable"));
        assert!(rendered.contains("Not reported"));
        assert!(rendered.contains("Disappearance is not verified remediation"));
        assert!(rendered.contains("Source authenticity: not established by parsing"));
        assert_eq!(
            rendered.matches("</th><td>").count(),
            4 * FIELD_LABELS.len()
        );
    }

    #[test]
    fn csp_permits_only_the_exact_static_script_and_styles() {
        let rendered = compare_reports(SAMPLE, SAMPLE, ComparisonFormat::Html).unwrap();
        assert_eq!(rendered.matches("<script>").count(), 1);
        assert_eq!(rendered.matches("</script>").count(), 1);
        assert!(rendered.contains(&format!(
            "script-src 'sha256-{}'",
            STANDARD.encode(Sha256::digest(SCRIPT))
        )));
        assert!(rendered.contains(&format!(
            "style-src 'sha256-{}'",
            STANDARD.encode(Sha256::digest(STYLE))
        )));
        for restriction in [
            "default-src 'none'",
            "base-uri 'none'",
            "connect-src 'none'",
            "form-action 'none'",
            "frame-src 'none'",
            "object-src 'none'",
        ] {
            assert!(rendered.contains(restriction));
        }
        for forbidden in [
            "innerHTML",
            "eval(",
            "fetch(",
            "localStorage",
            "serviceWorker",
            "onclick=",
            "unsafe-inline",
        ] {
            assert!(!rendered.contains(forbidden), "{forbidden}");
        }
        assert!(SCRIPT.contains(".textContent"));
        assert!(SCRIPT.contains("item.hidden=!matches"));
        assert!(SCRIPT.contains("empty.hidden=count!==0"));
        assert!(SCRIPT.contains("aria-pressed"));
        assert!(STYLE.contains(":focus-visible"));
        assert!(STYLE.contains("prefers-color-scheme:dark"));
        assert!(STYLE.contains("@media print"));
        assert!(STYLE.contains(".item[hidden]{display:block!important}"));
    }

    #[test]
    fn hostile_looking_imported_text_never_becomes_markup_or_a_link() {
        let mut value: Value = serde_json::from_slice(SAMPLE).unwrap();
        let hostile = "</script><img src=x onerror=alert(1)> javascript:alert(1) & \"quoted\"";
        value["items"][0]["redacted_summary"] = hostile.into();
        value["items"][0]["remediation"]["summary"] = hostile.into();
        let bytes = serde_json::to_vec(&value).unwrap();
        let rendered = compare_reports(SAMPLE, &bytes, ComparisonFormat::Html).unwrap();
        assert!(rendered.contains("&lt;/script&gt;&lt;img src=x onerror=alert(1)&gt;"));
        assert!(rendered.contains("&amp; &quot;quoted&quot;"));
        assert!(!rendered.contains("<img"));
        assert!(!rendered.contains("href=\"javascript:"));
        assert_eq!(rendered.matches("<script>").count(), 1);
        assert_eq!(rendered.matches("href=").count(), 1); // Fixed skip link only.
    }

    #[test]
    fn empty_reports_and_output_limit_fail_closed() {
        let mut value: Value = serde_json::from_slice(SAMPLE).unwrap();
        value["items"] = serde_json::json!([]);
        value["item_count"] = 0.into();
        let bytes = serde_json::to_vec(&value).unwrap();
        let document = compare_documents(
            import::parse(&bytes).unwrap(),
            import::parse(&bytes).unwrap(),
        )
        .unwrap();
        let rendered = render(&document, super::super::super::MAX_RENDERED_REPORT_BYTES).unwrap();
        assert!(rendered.contains("Both supplied complete reports contain no observations"));
        assert!(!rendered.contains("<article "));
        assert_eq!(
            render(&document, rendered.len() - 1),
            Err(ComparisonError::OutputLimitExceeded)
        );
        assert_eq!(render(&document, rendered.len()).unwrap(), rendered);
    }

    #[test]
    fn optional_imported_field_text_and_stage_are_visible_without_interpretation() {
        let bytes = SAMPLE;
        let mut document =
            compare_documents(import::parse(bytes).unwrap(), import::parse(bytes).unwrap())
                .unwrap();
        let projection = document.unchanged[0].after.as_mut().unwrap();
        projection.severity = Some("high".to_owned());
        projection.cwe = Some("CWE-79".to_owned());
        projection.evidence.verification_stage = Some("active".to_owned());
        let rendered = render(&document, super::super::super::MAX_RENDERED_REPORT_BYTES).unwrap();
        assert!(rendered.contains("<td>high</td>"));
        assert!(rendered.contains("<td>CWE-79</td>"));
        assert!(rendered.contains("<td>active</td>"));
        assert!(rendered.contains("Imported disposition"));
    }
}
