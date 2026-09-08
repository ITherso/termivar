# Synthetic Wordfence V3 Production-format fixture

`production.synthetic.json` is original fictional test data shaped from the
public Wordfence V3 Production feed documentation. It was not downloaded from
the feed, does not describe a real vulnerability, and is not evidence that a
Wordfence account, API key, current feed, or complete snapshot was available.
No API request or credential was used to create it.

The checked-in fixture is exactly 3,883 bytes with SHA-256
`d9ed3140f44ae1e0a3746beb9937de2d829d28c068101120a9104c3349901db7`.
This digest identifies these synthetic bytes; it is not a signature or source
authentication.

Exact committed-candidate fixture identity before any later review edits:

- byte length: `3883`;
- SHA-256: `d9ed3140f44ae1e0a3746beb9937de2d829d28c068101120a9104c3349901db7`.

Tests that intentionally mutate or reformat the fixture must use a temporary
copy. If the source fixture is deliberately edited during review, update both
values from its final exact bytes.

Primary format and access references:

- <https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/>
- <https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/>
- Wordfence CLI comparison implementation pinned at commit
  `6f1dfc39b2caad558d097404aab4bb0a1c018308`:
  <https://github.com/wordfence/wordfence-cli/blob/6f1dfc39b2caad558d097404aab4bb0a1c018308/wordfence/util/versioning.py>
- PHP 8.3.0 comparison implementation pinned at commit
  `d26068059e83fe40de3430a512471d194119bee0`:
  <https://github.com/php/php-src/blob/d26068059e83fe40de3430a512471d194119bee0/ext/standard/versioning.c>

The public format reference describes a root object keyed by vulnerability
UUID, Production records, software associations, structured affected-version
bounds, nullable source dates, and per-record copyright information. It also
states that feed access requires token authentication. This fixture tests only
offline decoding of bytes already supplied by an operator; it grants no API or
redistribution authority.

## Independently reviewed structural expectations

The fixture deliberately contains:

- 2 root vulnerability records whose object key equals the record `id`;
- 3 software associations: one core, one plugin, and one theme;
- 4 affected-version range entries: two plugin branches, one theme branch, and
  one core boundary;
- 3 source-declared patched versions across the records;
- 2 references and no assigned CVE identifiers;
- one record with source-declared `published` and `updated` values and one with
  both values explicitly `null`;
- one fictional copyright block with one fictional claimant, and one record
  whose `copyrights` value is `null`;
- the same synthetic slug in a plugin and a theme, which must remain distinct
  component identities;
- one whole-value `*` endpoint and one deliberate `1.0` versus `1.0.0`
  boundary.

The human-readable keys inside `affected_versions` are labels. The four nested
`from_version`, `from_inclusive`, `to_version`, and `to_inclusive` fields are the
structured range declarations. Only a whole-value `*` is the documented
wildcard sentinel. `1.*` is not a supported wildcard and must not be expanded.

These are parser-level expectations. Selection and evaluation counts depend on
the operator-supplied installation inventory. A conforming adapter must retain
the distinction between the three associations, read and validate the complete
file before assessment startup, and reconcile parsed, selected, evaluable,
unsupported, and excluded counts without calling omitted data complete.

## Comparison and rights boundary

The public feed format documents bounds and inclusivity but does not, by itself,
establish how every version spelling is ordered. In particular, this fixture's
`1.0` / `1.0.0` range must not be resolved by silently choosing whichever
existing Termivar profile produces a match. Without an explicit selector, the
association remains indeterminate in the v4 audit with a source-semantics
limitation.

For development-source acceptance, an operator may explicitly add exactly one
of these options to a scan that already selects this local Production-format
file:

```text
--wordpress-external-version-profile numeric-dotted/v1
--wordpress-external-version-profile php-release-subset/v1
```

That opt-in asks Termivar to evaluate the structured intervals under the named
local rule. It emits `security.wordpress-review-audit/v5` with
`comparison_policy=termivar.wordfence-v3-explicit-interpretation/v1`,
`policy_selection=explicit_operator`, and
`source_semantics_assurance=not_established`. It is not a claim about the
provider's normative comparator and cannot be selected implicitly or retried
under the other rule.

Under an explicit profile, a supported containing range can produce a
qualified positive while separately retaining an unsupported-range limitation.
An outside result requires every declared range to be conclusively outside.
Unsupported spellings, missing or conflicting versions, reversed bounds, and
equal exclusive-empty intervals remain indeterminate; ranges are not swapped,
dropped, or normalized into a preferred outcome.

The pinned Wordfence CLI implementation fills a missing sequence position with
a numeric zero, while the pinned PHP implementation underlying Termivar's
bounded PHP subset has different end-of-sequence behavior. That observed
implementation difference is evidence for this boundary test, not a declaration
that the V3 feed contract normatively selects either implementation.

All narrative, names, identifiers, references, and notice text in this fixture
are fictional and were written for Termivar. They do not reproduce a real
provider record or provider licence. A real operator-supplied export may contain
rights notices that must remain attached when its material is displayed or
exported. Parser success, a source URL, and a digest do not establish permission,
authenticity, freshness, or completeness.

This fixture must remain clearly labelled synthetic in generated examples and
test output. It must not be presented as live-feed acceptance or a vulnerability
detection benchmark. No authorized vendor export is supplied here, so
`real_export_acceptance=NOT_RUN_NO_INPUT` even when synthetic v4/v5 reader,
Verify, and Compare tests pass.
