# Versioned control-reference mapping

Status: Preview, explicit opt-in, development-only. The capability is outside
the default feature set, the seven-member `release-bundle`, and the published
`v0.10.0-alpha.2` archives.

## Selection and execution boundary

Build a development executable with the non-default feature and select it only
with an explicit web-review profile:

```bash
cargo build --locked -p termivar-cli --no-default-features \
  --features control-reference-mapping

termivar scan <AUTHORIZED_TARGET> \
  --profile web-review \
  --control-reference-mapping \
  --report-dir assessment-with-control-references
```

The option maps the completed typed assessment items produced by that same
assessment. It is not a scanner phase, a second assessment, a remote standards
client or an authority source. It adds exactly zero target requests, zero
provider requests and no source retrieval. Ordinary assessment traffic remains
owned and accounted for by the capabilities that selected it.

The operation is deterministic and bounded. It accepts at most 4,096 distinct
assessment items, retains at most 4,096 mapped-item relationships, at most
16,384 reference links overall and at most eight links for one item. Duplicate
item fingerprints, count overflow or a limit violation fail the mapping instead
of silently dropping a relationship. The mapper cannot mutate an item's stable
identity, evidence, severity, disposition, remediation or claim authority.

## Catalogue and audit identity

The built-in finite catalogue has these stable identities:

| Contract | Identity |
| --- | --- |
| Audit schema | `security.control-reference-mapping-audit/v1` |
| Mapping policy | `termivar.control-reference-mapping/v1` |
| Catalogue | `termivar.reviewed-control-references` |
| Catalogue revision | `2026-09-20.1` |
| Source-metadata review date | `2026-09-20` |

The audit records whether mapping was selected, the reviewed source records,
source-qualified relationships, and reconciled considered, mapped, unmapped,
reference-link and omitted counts. Its external-activity record says target
requests `0`, provider requests `0`, and source retrieval `not_performed`.
Claim-limit fields keep control assessment `not_performed` and compliance,
certification, legal conclusion and source authentication `not_established`.

An unmapped item means only that this exact finite catalogue contains no
eligible rule for the item's typed capability, CWE (when required) and
assessment basis. It does not mean the item is irrelevant to every framework.
An absent assessment item is not evidence that a control is fulfilled.

## Reviewed sources and rights posture

Source URLs are inert bibliography. The mapper never fetches them. A review
date and a valid identifier do not authenticate the source, establish that the
catalogue is complete or make a framework applicable to an organization.

| Source ID | Edition/reference | Retained mapping content | Rights posture |
| --- | --- | --- | --- |
| `owasp-top-10-2025` | OWASP Top 10:2025 | Reviewed identifiers and exact titles, attribution, applicability conditions and original Termivar rationales | identifiers and titles with attribution |
| `pci-dss-4.0.1` | PCI DSS 4.0.1, published 2024-06-11 | Bibliographic source metadata only; no PCI requirement mapping or standards prose | `rights_deferred` / bibliographic metadata only |
| `iso-iec-27001-2022-amd-1-2024` | ISO/IEC 27001:2022 with Amd 1:2024 | Bibliographic source metadata only; no Annex A/control mapping or standards prose | `rights_deferred` / bibliographic metadata only |
| `kvkk-law-6698-article-12` | Law No. 6698, Article 12 | Relevant technical-context links only, with legal applicability unestablished | official reference only |
| `kvkk-guide-72-2025-04` | Personal Data Security Guide, publication No. 72, April 2025 | Relevant technical-context references with original Termivar rationale; no guide text or claimed control result | official reference only |

The V1 rule set uses these exact OWASP Top 10:2025 references:

- `A01:2025` — `Broken Access Control`;
- `A02:2025` — `Security Misconfiguration`;
- `A05:2025` — `Injection`.

These are 2025 identifiers. Historical editions keep their historical IDs;
for example, a historical `A03:2021` reference must not be silently renamed to
the 2025 Injection identifier. A relationship stores an original Termivar
rationale and a precise applicability condition rather than copying OWASP body
text or treating the category title as a finding.

Specific redacted secret-exposure observations may carry both
`6698/Madde-12` and `KVKK-Rehber-72/2025-04` as relevant technical context.
This one-to-many case is explicit: neither link is a control result, and the
guide link is not copied guide text. Personal-data processing, organizational
scope, ownership, validity and legal applicability remain unestablished. The
output is not legal advice.

Primary bibliography:

- [OWASP Top 10:2025](https://top10.owasp.org/2025/0x00_2025-Introduction/)
- [PCI SSC: PCI DSS v4.0.1 publication](https://blog.pcisecuritystandards.org/just-published-pci-dss-v4-0-1)
- [ISO/IEC 27001](https://www.iso.org/standard/27001)
- [KVKK Article 12 responsibilities](https://www.kvkk.gov.tr/Icerik/2040/Veri-Guvenligine-Iliskin-Yukumlulukler)
- [KVKK Personal Data Security Guide, publication No. 72](https://kvkk.gov.tr/SharedFolderServer/CMSFiles/7512d0d4-f345-41cb-bc5b-8d5cf125e3a1.pdf)

These links are development/reference destinations, not scan-time targets.

## Relationship semantics

A relationship is emitted only when the item's exact typed capability identity,
optional CWE requirement and assessment-basis class match one or more reviewed
rules. Multiple eligible sources can link to one item, and one reference can be
relevant to multiple items; neither direction strengthens claim authority.
Rule matching is not a free-text search, nearest-category guess or severity
lookup. The link retains:

- a stable Termivar rule ID;
- source/framework and exact reference identifiers;
- an exact title only when the retained rights posture permits it;
- the typed mapping basis and assurance;
- an explicit applicability state and condition;
- an original Termivar rationale.

The relationship describes why an already-produced observation may be useful
technical context for a reviewer. It does not establish that a framework
requirement applies, that a control was assessed, that the organization passed
or failed, or that the assessment item is a confirmed vulnerability.

No relationship may:

- raise or lower severity;
- change `Informational`, `NeedsReview` or another disposition;
- increase evidence or claim authority;
- create a score, percentage, pass/fail result or certification;
- make a legal or organization-wide compliance conclusion;
- authenticate a source, target or organization;
- infer fulfilment from the absence of an item.

The older scanner `compliance` feature remains an experimental caller-supplied
record scaffold with no repository product execution path. This capability does
not repurpose it or turn it into a compliance engine.

## Saved reports, Verify and Compare

The mapping audit is an optional section in the existing central assessment
report and bundle; it is not a second report or a new command. Human output must
present it as technical reference context and keep the claim limits visible.
Machine output retains bounded relationship and accounting data without
embedding restricted standards text.

Report Verify checks the supported bundle bytes, manifest, assessment schema and
internal count consistency. `integrity_match` does not establish catalogue
truth, source authenticity, framework applicability, control fulfilment,
compliance or legal meaning.

Report Compare keeps item changes separate from mapping methodology. A changed
catalogue revision, source edition/rights status, rationale or relationship set
is a methodology/source change. It is not a target change, new vulnerability,
remediation, compliance transition or control-status change. The ordinary
comparison continues to expose its four top-level arrays—`only_in_after`,
`only_in_before`, `changed`, and `unchanged`; there is no top-level `counts`
object.

## Acceptance boundaries

Useful acceptance covers an option-off run, an explicitly selected empty audit,
mapped and unmapped typed items, deterministic ordering, exact source metadata,
duplicate/limit rejection, zero external activity, bundle rendering, Verify,
self-Compare and a controlled catalogue/source-methodology comparison. Tests use
literal independent expectations; deriving the expected feature set or mapping
answer from the producer under test would not be an independent oracle.

Compilation alone is not execution acceptance. Inclusion in an all-features
development build is not inclusion in `release-bundle`, and neither is a
published release. The current published prerelease remains `v0.10.0-alpha.2`.
