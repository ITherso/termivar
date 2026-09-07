# WordPress evidence review

The optional `wordpress-review` feature adds bounded WordPress-specific
interpretation to the existing `web-review` assessment. It does not start a
WordPress-specific scanner. It interprets signals from the root HTML response
that the assessment already obtained, plus explicitly supplied local context
and advisory data. Enabling it adds no target or provider requests.

This source feature is non-default and is not part of the curated release
bundle. A binary must be compiled with `wordpress-review` before the flags are
available. Compile-time inclusion does not enable the review; the operator must
also select it explicitly:

```bash
termivar scan https://authorized.example/ \
  --profile web-review \
  --wordpress-review \
  --wordpress-context wordpress-context.json \
  --wordpress-advisories wordpress-advisories.json \
  --report-dir assessment-wordpress
```

`--wordpress-context` and `--wordpress-advisories` each require
`--wordpress-review`, and the review requires an explicit `--profile
web-review`. Termivar validates and bounds both local files before loading
secrets or constructing the scanner runtime. The CLI owns the file access; the
runtime receives validated values and no filesystem authority. The hardened
reader opens the final path component without following links and validates the
opened handle as a regular file; parent directories remain a trusted boundary.
Special files, malformed documents, duplicate keys, conflicting identities,
and limit violations are rejected.

## What can be observed

V1 recognizes only supported structured data in the already captured root
HTML:

- WordPress generator metadata in the expected `meta` element and attributes;
- canonical same-origin asset-path hints for WordPress core, plugin, and theme
  identities.

The WordPress function reference documents that its HTML generator output is a
`meta` element whose content contains `WordPress` and the public version. The
same reference also documents a filter over generator output. Termivar
therefore treats this as a public declaration, not authenticated proof of the
installed source or patch state. See
<https://developer.wordpress.org/reference/functions/get_the_generator/>.

An eligible asset path can suggest a component identity. It does not establish
that the component is installed, active, or executing on the server. Query
parameters on an asset are not accepted as installed component versions.
Article prose, comments, script strings, malformed elements, and foreign-origin
assets do not establish WordPress identity. Missing hints do not establish
absence, including when sites use custom content paths or content delivery
networks.

Every result keeps the identity source, version source, confidence, and any
contradiction separate. Repetition is not treated as independent evidence, and
no declaration wins merely because it was seen last. V1 retains its numeric
conflict rules; V2 decides semantic equivalence or conflict separately under
each record's explicit comparison profile.

## Operator context

The context schema is `security.wordpress-context/v1`. A document names one
exact root and up to 256 declared components. The root must match the scan's
exact origin root and may not contain credentials, a query, or a fragment.
Components have a closed `core`, `plugin`, or `theme` kind; core uses the slug
`wordpress`, while plugin and theme slugs use bounded canonical lowercase
identifiers.

An optional version remains an operator-supplied string. Optional activation
states are `active`, `inactive`, `network_active`, or `unknown`. Optional facts
are limited to a closed hosting-OS classification, multisite state, and up to 32
bounded patch declarations per component. Omitted components and facts are
unknown, not absent. A supplied status or patch declaration is not live
authentication of the installation.

The context can be assembled from trusted operator inventory. The official
WP-CLI `plugin list` documentation describes fields including `name`, `status`,
and `version`, and activation states including active, network-active, and
inactive: <https://developer.wordpress.org/cli/commands/plugin/list/>. The V1
Termivar context normalizes WP-CLI's `active-network` spelling to
`network_active`. Termivar also accepts the bounded saved-inventory projection
described below. It never invokes WP-CLI or PHP.

The complete context file is limited to 1 MiB. See
[`docs/examples/wordpress-review/context.synthetic.json`](examples/wordpress-review/context.synthetic.json)
for a deliberately fictional declaration.

## Saved WP-CLI inventory

Instead of authoring `security.wordpress-context/v1`, an operator can save
three narrow WP-CLI projections before the assessment:

```bash
wp plugin list --fields=name,status,version --format=json > wordpress-plugins.json
wp theme list --fields=name,status,version --format=json > wordpress-themes.json
wp core version > wordpress-core-version.txt
```

Termivar reads only files already produced by the operator. It does not start
WP-CLI, PHP, WordPress, or another subprocess. Select any nonempty combination
of the three inputs with their exact CLI options:

```bash
termivar scan https://authorized.example/ \
  --profile web-review \
  --wordpress-review \
  --wordpress-plugins-json wordpress-plugins.json \
  --wordpress-themes-json wordpress-themes.json \
  --wordpress-core-version-file wordpress-core-version.txt \
  --wordpress-advisories wordpress-advisories.json \
  --report-dir assessment-wordpress
```

The saved-inventory options conflict with `--wordpress-context`; they are an
alternate source for the same bounded operator-context role. Advisory input is
independent and may be supplied with either form. All selected inventory files
share one 1 MiB ceiling and one 256-entry ceiling. Plugin and theme inputs must
be JSON arrays whose rows contain bounded `name`, `status`, and `version`
strings. The core input is one version line of at most 64 bytes, with at most
one final LF or CRLF. Duplicate object keys, duplicate component identities,
unknown fields or statuses, malformed JSON, and limit violations fail closed.

Supported plugin statuses are `active`, `inactive`, `active-network`,
`must-use`, and `dropin`. Supported theme statuses are `active`, `inactive`,
and `parent`. `active-network` becomes the typed `network_active` activation.
That row describes only the supplied WP-CLI inventory entry; it does not prove
the complete activation topology of a multisite network.
`must-use` and theme `parent` are retained as inventory classifications without
inventing a normal activation state. A drop-in name such as `object-cache.php`
is a filename, not a canonical plugin catalogue slug; it is therefore reported
as an explicit inventory limitation and is not evaluated as an advisory
component. Update-related WP-CLI fields, when present in the bounded accepted
shape, are informational only and never become patch or remediation evidence.

These files are operator-supplied, unauthenticated declarations. Termivar binds
them to the exact origin selected by the invocation, but parsing does not prove
that WP-CLI produced them, that they are complete, or that they describe that
origin. A category that was not supplied is `not_supplied`, which means unknown,
not empty. Even a supplied empty array does not authenticate absence. Input
paths are not retained in the assessment. The report records fixed input class,
exact byte length, and SHA-256 for byte identification; a digest is not a
signature or source authentication.

The hardened reader opens the final path component without following links and
validates the same opened handle as a regular file. Parent directories remain a
trusted boundary; this is not whole-path containment or a concurrent filesystem
snapshot. Saved inventory is parsed before credentials or scanner construction,
adds no target/provider requests, and remains operator context in the existing
single assessment runtime.

Saved inventory produces the additive
`security.wordpress-review-audit/v3` shape so coverage, entry classifications,
limitations, and input-byte provenance remain explicit. It does not alter the
stable context or advisory schemas. Raw version strings remain evidence. A V1
catalogue still uses `numeric-dotted/v1`; a V2 catalogue evaluates them under
each record's explicit comparison profile. An unsupported version stays
indeterminate rather than selecting a profile or falling back automatically.

See the clearly fictional files and commands in the
[`saved-inventory` example README](examples/wordpress-review/saved-inventory/README.md).

## Advisory snapshots

The advisory schema is `security.wordpress-advisory-catalog/v1`. A catalogue
contains a bounded identity, revision, retrieval date, and no more than 4,096
records. Each record names exactly one component and carries its own source
reference, source revision, retrieval date, and usage-basis note. A record can
contain at most 16 explicit version intervals, 16 fixed-version declarations,
and eight typed prerequisites.

Advisory files are data, never executable policy. They cannot contain regular
expressions, scripts, request templates, payloads, or commands. References are
inert bibliography; they are not fetched during a scan. Termivar does not
query vulnerability databases or claim that a supplied snapshot is current or
comprehensive. Without a file the report says `catalogue_not_supplied`. With a
file, no matched record means only that no match occurred in that supplied
snapshot.

V1 compares numeric-dotted release tuples of one to eight components in at
most 64 UTF-8 bytes. Each component contains ASCII digits only, has no
multi-digit leading zero, and is parsed with checked `u32` arithmetic. Trailing
zero components normalize away (for example, `1.2` and `1.2.0` compare
equally). Prefixes, suffixes, empty components, and overflowing components are
unsupported and therefore indeterminate. This profile is intentionally
narrower than PHP's `version_compare()`: the PHP manual documents normalization
and ordering for separators and labels such as `dev`, `alpha`, `beta`, and
`RC`. Termivar neither implements that full behavior nor runs PHP. See
<https://www.php.net/manual/en/function.version-compare.php>.

### Explicit comparison profiles

`security.wordpress-advisory-catalog/v2` requires every record to select one
closed `comparison_profile`. `numeric-dotted/v1` is exactly the V1 comparator
described above; its parsing and trailing-zero equality are unchanged.
`php-release-subset/v1` is an additive, deliberately bounded interpretation of
common PHP-style release forms. The profile belongs to advisory data, not to
the observed version string: Termivar does not infer it from a suffix, vendor,
host, or whichever comparator might produce a match. Missing and unknown
profiles make the catalogue invalid before runtime construction.

The PHP release subset accepts nonempty ASCII strings of at most 64 bytes with
one to eight numeric release components. Numeric components are in
`0..=2147483647`, contain no more than ten digits, and may contain leading
zeroes. Single `.`, `-`, `_`, or `+` separators are accepted between numeric
components. One optional recognized suffix may follow the core, adjoining it
or following one such separator: `dev`, `alpha`/`a`, `beta`/`b`, `RC`/`rc`, or
`pl`/`p`. One optional numeric suffix counter may likewise adjoin the suffix or
follow one separator. `+` is a separator here, not SemVer build metadata.

Unknown or vendor labels, other case variants, `v` prefixes, whitespace,
controls, doubled/leading/trailing separators, multiple suffixes, arbitrary
build text, overflow, and excessive tokens remain unsupported. Termivar does
not strip unknown text into a guessed order. The accepted token sequence uses
the ordering of the documented PHP release forms, including PHP's treatment of
numeric, prerelease, final, and patch-level parts. It intentionally does not
inherit numeric-dotted trailing-zero normalization: `1.0` equals `1.0.0` under
`numeric-dotted/v1`, while `1.0` sorts before `1.0.0` under
`php-release-subset/v1`. Aliases such as `1.0-alpha1` and `1.0a1` compare
equally within the PHP subset. This is not full PHP compatibility, SemVer,
Composer constraint support, or automatic interpretation of vendor schemes.

The V2 evaluator resolves all version evidence separately for each record's
selected profile. Its saved `security.wordpress-review-audit/v2` record shows
the `comparison_profile`, a bounded `version_resolution`, and the corresponding
reason alongside the existing relation, prerequisites, source basis, and
uncertainty. Unsupported evidence remains evidence; it is not discarded or
retried with another profile. A profile change is a methodology difference,
not proof that an installation changed or was remediated. V1 catalogues retain
the existing `security.wordpress-review-audit/v1` shape.

The V2 component-level evidence class describes only provenance (observed hint,
operator-supplied, or unknown). Semantic version equivalence, conflict, and
unsupported input are reported per advisory record under its selected profile;
they are not collapsed into one global numeric interpretation.

The subset is based on the public PHP `version_compare()` description and the
pinned PHP 8.3.0 implementation source at commit
`d26068059e83fe40de3430a512471d194119bee0`. The source is a comparison
reference, not a runtime dependency:
<https://github.com/php/php-src/blob/d26068059e83fe40de3430a512471d194119bee0/ext/standard/versioning.c>.

The evaluator checks component identity before version intervals and reports
version relation and each prerequisite separately. It does not infer an open
lower bound merely because a bulletin names a fixed version. Disjoint
maintained branches remain separate. Unsupported prerequisites remain
unevaluated rather than being discarded. Prerequisites are conjunctive: an
outside declared range or a supported prerequisite contradicted by supplied
facts makes the summary contradicted even when another prerequisite is
unsupported; absent a contradiction, unsupported evidence remains
indeterminate rather than becoming a match.

The example directory contains three catalogue examples:

- [`advisories.curated.json`](examples/wordpress-review/advisories.curated.json)
  is one manually curated factual record from an official WordPress project
  advisory. It is a small example, not a vulnerability feed.
- [`advisories.synthetic.json`](examples/wordpress-review/advisories.synthetic.json)
  uses unmistakably fictional component and record identities to exercise
  matched, contradicted, and unsupported-version decisions. These are not
  alleged vulnerabilities.
- [`advisories.profiles.synthetic.json`](examples/wordpress-review/advisories.profiles.synthetic.json)
  and its paired
  [`context.profiles.synthetic.json`](examples/wordpress-review/context.profiles.synthetic.json)
  exercise explicit V2 profile selection, prerelease interpretation,
  profile-dependent trailing-zero behavior, and rejection of a fictional
  vendor label. They are comparison fixtures, not alleged vulnerabilities.

### Local Wordfence V3 Production-format exports (development source)

The feature-enabled development CLI accepts an explicitly selected, already
saved Wordfence V3 Production-format JSON file through the existing assessment:

```bash
termivar scan <AUTHORIZED_EXACT_ROOT> \
  --profile web-review \
  --wordpress-review \
  --wordpress-advisories wordfence-production.json \
  --wordpress-advisories-format wordfence-v3-production \
  --report-dir <NEW_REPORT_DIRECTORY>
```

Omitting `--wordpress-advisories-format` retains the existing strict Termivar
catalogue parser. The choice is never inferred from a filename or document
contents, and there is no fallback between the two formats.

The adapter does not obtain an API key, call Wordfence, discover a credential,
or fetch a reference during an assessment. The operator remains responsible for
obtaining and storing any export under the source's current terms. Wordfence's
public documentation states that the V3 feed requires token authentication and
describes distinct Production and Scanner formats. This scope accepts Production
format only; it does not infer a format from a filename or fall back to the
Scanner format.

The declared source file is read completely within a separate bounded
external-import policy before runtime startup. The current hard ceilings are
256 MiB of input, 100,000 records, 200,000 software associations, 512 KiB per
record, and 64 MiB of conservatively accounted retained index data; narrower
per-field, range, and output limits also apply. Crossing a bound fails explicitly
rather than truncating the source. Root UUID keys, record IDs,
software associations, structured range bounds, patched-version declarations,
nullable source dates, references, and rights notices remain source-qualified
metadata. A patched flag or fixed-version declaration does not prove that the
selected installation contains a fix. A source CVSS value is not a
Termivar-calculated installed risk score.

When a selected record carries Defiant copyright terms, preflight requires an
existing source-declared Wordfence vulnerability-record reference. Only the
documented `www.wordfence.com/threat-intel/vulnerabilities/` HTTP/HTTPS form is
accepted; Termivar neither invents nor fetches a missing link. The report emits
that record link together with the retained notice and licence text. A missing
required link rejects the input before the assessment starts rather than
silently publishing an attribution-incomplete copy.

The source format specifies structured range endpoints and inclusivity, but it
does not by itself establish a comparison algorithm for every vendor version.
Termivar must not assume that the provider's semantics equal either
`numeric-dotted/v1` or `php-release-subset/v1`. Unsupported or unresolved source
semantics remain indeterminate rather than being tried under both profiles until
one yields a preferred result. The `1.0` versus `1.0.0` boundary is an explicit
regression case for this distinction.

Reports identify the external format and mapping revision, preserve the
exact-input byte length and digest, reconcile parsed/association/selected/
evaluable/unsupported/excluded counts, and retain required notices for material
they display. These values identify the processed bytes and interpretation; they
do not authenticate the source, prove snapshot completeness, or establish a
collection timestamp. Source-declared `published` and `updated` values remain
distinct from collection time. A filesystem modification time is not substituted
for any of them.

The independently written
[`wordfence-v3` synthetic fixture](examples/wordpress-review/wordfence-v3/README.md)
records the public-schema-only expectations used by the parser and end-to-end
acceptance. It is not a live export, no provider credential was used, and this
does not establish compatibility with a complete current feed snapshot.

## Reading the WordPress report

The HTML and Markdown assessment reports present operator-relevant fields from
the same typed WordPress audit in structured sections. **Source and coverage**
identifies the native
catalogue or external snapshot, its normalization/comparison policy, saved
inventory category coverage, and reconciled association counts. **Component
evidence** keeps observed root-response hints distinct from operator-supplied
inventory declarations and shows every retained version with its source and
confidence class.

Advisory evaluations are mutually grouped as **Review candidates**,
**Contradicted on supplied facts**, or **Evaluation limitations**. A review
candidate means only that the supplied declarations matched the supported
catalogue rule. A contradicted result does not establish that the installation
is safe. Missing or conflicting versions, unknown prerequisites, unsupported
ranges, and unresolved source-comparison semantics remain visible as
limitations rather than disappearing from the report.

Fixed or patched versions and remediation text are labelled
**source-declared remediation information**. They are guidance for the
operator's normal compatibility and update process, not an automatic update or
a verified local fix. The report states `exploit_execution=not_performed` and
`impact_validation=not_performed`; association counts are not added to the one
WordPress surface observation as vulnerability counts.

JSON retains the complete versioned audit contract and CSV retains its existing
bounded audit projection. Offline Verify checks the saved document and bundle
contract, not advisory truth. At this stage Report Compare preserves and shows
the optional audit bytes but does not yet attribute WordPress changes to
inventory, advisory, or methodology causes; use its result as a document
comparison, not remediation proof.

## Result and claim limits

The WordPress audit belongs to the same final assessment report and evidence
lifecycle as every other review. It shows observed and operator-declared
component evidence, catalogue coverage, interval and prerequisite decisions,
source references, uncertainty, and catalogue-supplied, source-attributed
remediation text. It does not finalize a detached report or grant execution
authority.

Supported structured signals from the existing root response may project one
`technology.wordpress-surface-observed@1` item. That item is
`Informational` / `KnowledgeOnly` and describes only the observed surface
hints. Advisory applicability remains typed audit data: even
`candidate_match_on_declared_facts` does not mint a `NeedsReview` item because
the review has no differential verification evidence. Operator declarations
show what was declared, not authenticated live state. `exploit_execution` and
`impact_validation` remain `not_performed`. Termivar does not synthesize CVSS,
claim a confirmed vulnerability, prove that a fix is absent, or infer that the
installation is safe from a contradicted condition.

Reports describe the supplied catalogue identity, revision, retrieval date,
source reference, and evaluation result. The curated example README separately
records the exact-byte SHA-256 of its catalogue snapshot. A URL or digest can
identify supplied bytes but does not authenticate the source or the operator's
inventory. Report strings remain untrusted text subject to the existing output
bounds and escaping; escaping is not generic secret removal.

The existing report bundle contains the same assessment rendered once into its
normal formats. Offline bundle verification checks supported structure and
bytes, not advisory truth. Offline Report Compare can show that WordPress
evidence or conclusions changed, but disappearance is not verified
remediation. The matching development reader accepts the optional WordPress
audit. The already-published `v0.10.0-alpha.2` Compare and Verify importers
predate this additive field and reject WordPress-extended assessment JSON; use
the matching development reader or a later release for those files. Neither
offline command starts a scan or adds network requests.

## Source and scope notes

The existing development references were reviewed on 2026-09-06. The pinned
PHP implementation reference for the comparison profiles was additionally
reviewed on 2026-09-07:

- WordPress generator function reference:
  <https://developer.wordpress.org/reference/functions/get_the_generator/>
- WP-CLI plugin inventory fields and states:
  <https://developer.wordpress.org/cli/commands/plugin/list/>
- WP-CLI theme inventory fields and states:
  <https://developer.wordpress.org/cli/commands/theme/list/>
- WP-CLI core version output:
  <https://developer.wordpress.org/cli/commands/core/version/>
- Wordfence V3 Production/Scanner format and authenticated access contract:
  <https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/>
- Wordfence Intelligence terms reviewed for copy/attribution requirements:
  <https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/>
- Wordfence CLI comparison implementation pinned at commit
  `6f1dfc39b2caad558d097404aab4bb0a1c018308`:
  <https://github.com/wordfence/wordfence-cli/blob/6f1dfc39b2caad558d097404aab4bb0a1c018308/wordfence/util/versioning.py>
- PHP version comparison behavior (broader than Termivar's V1 profile):
  <https://www.php.net/manual/en/function.version-compare.php>
- PHP 8.3.0 comparison implementation pinned at commit
  `d26068059e83fe40de3430a512471d194119bee0`:
  <https://github.com/php/php-src/blob/d26068059e83fe40de3430a512471d194119bee0/ext/standard/versioning.c>
- WordPress security-release index:
  <https://wordpress.org/news/category/security/>

WordPress software is distributed under GPLv2 or later according to
<https://wordpress.org/about/license/>. That software license is not presented
here as a blanket licence for advisory prose or a vulnerability database. The
curated example records only a few attributed factual identifiers and explicit
version bounds from the linked official project advisory; it does not copy the
advisory narrative or imply permission for bulk redistribution. WordPress is a
registered trademark of the WordPress Foundation; Termivar is not affiliated
with or endorsed by the WordPress project.
