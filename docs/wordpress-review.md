# WordPress evidence review

The optional `wordpress-review` feature adds bounded WordPress-specific
interpretation to the existing `web-review` assessment. It does not start a
WordPress-specific scanner. It interprets signals from the root HTML response
that the assessment already obtained, plus explicitly supplied local context
and advisory data. Selecting `--wordpress-review` alone adds no target or
provider requests. The separate `--wordpress-discovery` switch described below
explicitly authorizes a small bounded set of additional anonymous metadata
GETs through the same assessment broker.

This feature remains absent from the ordinary default build. The current
untagged `0.10.0-alpha.3` development `release-bundle` compiles it as a Preview;
the published alpha.2 archives predate all WordPress producer and audit support.
A binary must be compiled with `wordpress-review` before the flags are available.
Compile-time inclusion does not enable the review; the operator must also select
it explicitly:

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

## Explicit public-metadata discovery

Current development builds compiled with `wordpress-review` expose a separate
Preview option:

```bash
termivar scan http://127.0.0.1:8088/ \
  --profile web-review \
  --wordpress-review \
  --wordpress-discovery \
  --progress \
  --report-dir assessment-wordpress-discovery
```

The numeric loopback address is illustrative and assumes an already running,
operator-authorized fixture. Termivar does not start WordPress. The discovery
option requires the explicit review and `web-review` profile; merely compiling
the feature or selecting `--wordpress-review` does not enable network work.

When selected, discovery freezes candidates from structured links in the
committed root response and sends only anonymous, bodyless GETs through the
existing exact-origin broker. It does not inherit Authorization, Cookie, or
proxy credentials, and the discovery-only client does not use ambient proxy
configuration. Redirects and retries remain disabled. The WordPress
narrowing policy admits at most 12 wire attempts: one advertised REST index,
three theme stylesheets including at most one parent edge, and eight plugin
readmes. It is sequential, retains at most 32 candidates, records when a later
parent-theme declaration could not fit that cap, and has fixed
per-response and aggregate byte ceilings underneath the existing assessment
request, response, deadline, and cancellation limits. An attempt and a
completed, parsed, committed source are reported separately. As with the
parent broker, a delivered transport chunk can cross a retained-byte threshold
before cancellation; the ceilings are not described as a perfect wire cutoff.

Candidates are evidence-derived, not a wordlist:

- a `Link` header or HTML link whose exact relation is
  `https://api.w.org/` can nominate the same-origin REST root;
- a structured same-origin asset under
  `wp-content/themes/<slug>/...` can nominate only that theme's root
  `style.css`;
- a structured same-origin asset under
  `wp-content/plugins/<slug>/...` can nominate only that plugin's root
  `readme.txt`;
- a valid child-theme `Template` header can nominate one same-root parent
  stylesheet at depth one.

The REST query form is closed: the current WordPress source emits
`/index.php?rest_route=/` when pretty permalinks are disabled. The historical
handbook illustration `/?rest_route=/` remains useful context, but the current
core form is exercised by the pinned real-CMS lab. Extra or duplicate query
parameters, other routes, userinfo, fragments, encoded separators/traversal,
foreign origins, and a different loopback port are rejected. Termivar fetches
the REST index only; it does not traverse users, posts, settings, authentication
links, registered routes, or an API namespace.

The REST index retains only a bounded list of namespaces. `wp/v2` means core
REST endpoint support, not WordPress 2.x. A namespace such as
`termivar-lab/v1` is a protocol namespace and is neither a reliable plugin
directory identity nor an installed plugin version.

A theme stylesheet is interpreted from its bounded initial header section.
The identity remains the validated source path. `Version` is the served
artifact's declaration; `Template` is a parent-directory declaration; and
`Requires at least`, `Tested up to`, and `Requires PHP` are compatibility
statements, not installed core/PHP versions. A served file can be copied,
cached, or stale, so even a valid declaration is source-qualified observation,
not authenticated installation or patch state.

A plugin readme contributes its display header, requirements, and Stable tag.
The Stable tag identifies a distribution/repository release pointer. It is
never inserted into the installed-version evidence collection, even if its
spelling is a supported version. Termivar does not fetch plugin PHP entrypoints
or inspect server source to fill that gap. `trunk` and unsupported tags remain
nonversion hints.

The additive top-level `security.wordpress-discovery-audit/v1` records the
selection policy, anonymous GET method, seed/candidate/attempt/completion/commit
counts, accounted response bytes, outcomes, typed metadata, and evidence
reference counts. A discovery-influenced review uses the additive strict
`security.wordpress-review-audit/v7` wrapper. Its required
`review_basis_schema` preserves which v1–v6 evaluation contract supplied the
review facts, while `additional_request_count` records the actual discovery
attempt count. With discovery absent, historical v1–v6 output stays unchanged
and retains `additional_request_count=0`. Current Compare/Verify readers accept
the coordinated v7 review and top-level discovery audit without compiling the
producer feature. Compare applies the recorded review basis to component and
advisory semantics while treating collection policy and request coverage as
separate dimensions. A review-only versus discovery comparison is therefore
not a newly introduced vulnerability or remediation.

No eligible source, a 404, unsupported content, throttling, truncation, or a
budget/deadline stop remains visible as limited collection. It is never a
secure/clean result. Generator absence after an operator or plugin suppresses
it likewise remains unknown. Discovery can supply a source-qualified theme
version to the existing advisory evaluator, but a range match still does not
establish authenticated installation, exploitability, impact, or remediation.
`exploit_execution` and `impact_validation` remain `not_performed`.

The disposable real-WordPress acceptance design, independent WP-CLI ground
truth, exact four-request delta, pinned image identities, and licensing notes
are in the
[`discovery-lab` example](examples/wordpress-review/discovery-lab/README.md).

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

By default, Termivar preserves the external source-comparison limitation: it
selects relevant associations but does not guess how the source intended every
version spelling to be ordered. Within the historical identity and resource
envelope, that unchanged path emits `security.wordpress-review-audit/v4` with
`wordfence-v3/source-semantics-unresolved/v1` and indeterminate relations.
When the expanded source-identity or resource metadata described below is
needed, the same unresolved policy is carried by audit v6 instead.

An operator can instead request one reproducible Termivar interpretation for
the supplied external snapshot:

```bash
termivar scan <AUTHORIZED_EXACT_ROOT> \
  --profile web-review \
  --wordpress-review \
  --wordpress-advisories wordfence-production.json \
  --wordpress-advisories-format wordfence-v3-production \
  --wordpress-external-version-profile php-release-subset/v1 \
  --report-dir <NEW_REPORT_DIRECTORY>
```

The accepted values are `numeric-dotted/v1` and
`php-release-subset/v1`. This option is valid only with an explicitly supplied
`wordfence-v3-production` file, `--wordpress-review`, and `--profile
web-review`; it does not override native Termivar catalogue records. Termivar
never selects a profile from the filename, source URL, component kind, or the
outcome it would produce, and it never retries unsupported input under the
other profile.

Within the historical identity and resource envelope, explicit selection emits
`security.wordpress-review-audit/v5`; audit v6 carries the same fields when its
expanded metadata is needed. Both record:

- `comparison_policy=termivar.wordfence-v3-explicit-interpretation/v1`;
- the selected `comparison_profile`;
- `policy_selection=explicit_operator`;
- `source_semantics_assurance=not_established`.

These fields mean that the operator asked Termivar to apply a named local rule.
They do not claim that Wordfence selected or endorses the rule, that the rule
matches every component vendor, or that the local inventory is authentic.

The adapter does not obtain an API key, call Wordfence, discover a credential,
or fetch a reference during an assessment. The operator remains responsible for
obtaining and storing any export under the source's current terms. Wordfence's
public documentation states that the V3 feed requires token authentication and
describes distinct Production and Scanner formats. This scope accepts Production
format only; it does not infer a format from a filename or fall back to the
Scanner format.

### External source identities

The provider's component kind and slug are retained as a source identity before
Termivar attempts to match them to the native canonical component identity.
This keeps source spelling and case visible instead of rewriting the supplied
record. Native operator and observed component identities retain their existing
lowercase canonical rules.

The mapping revision `termivar-wordfence-v3-production/v2` uses the explicit
policy
`termivar.wordfence-v3-exact-plus-ascii-lowercase-candidate/v1`. Its four
outcomes have deliberately different authority:

- `exact` means the source kind and slug already form the same canonical
  identity without rewriting. Only exact associations can support a decisive
  version-range result under an explicitly selected comparison profile.
- `ascii_case_fold_candidate` means ASCII lowercase produces a valid canonical
  lookup key and only one distinct source spelling maps to that key in the
  supplied snapshot. It can surface a potentially relevant association, but it
  remains indeterminate because Termivar has not established that the source
  considers the spellings equivalent.
- `ascii_case_fold_ambiguous` means multiple distinct source spellings map to
  the same candidate key. The collision count and original spelling are
  retained; Termivar does not select a winner or produce a decisive version
  relation from that candidate.
- `unresolved` means no safe canonical candidate exists. The association and
  its ranges and patched-version declarations remain included in ingestion and
  resource accounting, but are not silently treated as irrelevant, absent, or
  unaffected.

Source slugs are bounded to 128 ASCII bytes. Controls and unsupported structural
forms are rejected; accepted noncanonical spellings remain inert identifiers
and are never interpreted as a path, URL, or normalization instruction.
Malformed values and resource violations still fail the import. Case folding is
a Termivar matching aid, not provider endorsement, package-directory validation,
installation authentication, or permission to fetch more data. Reports retain
`identity_source_assurance=not_established` and reconcile exact, candidate,
ambiguous, and unresolved association counts separately.

The declared source file is read completely within a separate bounded
external-import policy before runtime startup. The current largest resource
policy is `termivar.wordfence-v3-bounded-capacity/v3`. Its finite ceilings are
256 MiB of raw input, 100,000 records, 200,000 software associations, 768 KiB
per record, and 160 MiB of conservatively accounted import data. A
decoded object may contain at most 128 JSON members; one software association
may contain at most 128 affected ranges and 128 patched-version declarations.
The generic decoded-string and description ceilings are 4 KiB, while existing
stricter field-specific ceilings still apply. Source slugs have the separate
128-byte limit described above. The raw-input, record-count, and association-
count ceilings are unchanged from the earlier policy.

Inputs that remain within the historical 64 MiB envelope retain resource-policy
ID `termivar.wordfence-v3-bounded-capacity/v1`. V2 retains its historical
128 MiB ceiling, while V3 identifies imports that require the additive 160 MiB
envelope. The selected ID reflects the largest conservatively charged parse,
identity-resolution, or retained-index phase, so a temporary phase that exceeds
an older ceiling is not labelled as having fit it. Expanded source field/list
semantics still require at least V2 even when their byte charge is small.
These IDs describe Termivar's bounded decoder, not the provider's feed
completeness or a promise that every simultaneous maximum will fit. The limits
are joint, use checked accounting, and remain subject to narrower evaluator,
work, field, and report ceilings. The retained-import charge covers retained
records, strings, notices, indexes, and bounded parse-time identity structures;
it is a conservative application accounting policy, not an operating-system
RSS or heap guarantee.
Crossing any effective bound fails explicitly rather than
truncating the source. Root UUID keys, record IDs,
software associations, structured range bounds, patched-version declarations,
nullable source dates, references, and rights notices remain source-qualified
metadata. A patched flag or fixed-version declaration does not prove that the
selected installation contains a fix. A source CVSS value is not a
Termivar-calculated installed risk score.

When a selected record carries Defiant copyright terms, preflight requires an
existing source-declared Wordfence vulnerability-record reference. Only the
documented `www.wordfence.com/threat-intel/vulnerabilities/` HTTP/HTTPS form is
accepted. The record link may have no query or exactly one literal `source`
parameter whose value is 1–64 unreserved ASCII characters; other, empty,
duplicate, encoded, or multi-parameter query forms are rejected. Termivar
neither invents nor fetches a missing link. The report emits that exact record
link together with the retained notice and licence text. A missing required
link rejects the input before the assessment starts rather than silently
publishing an attribution-incomplete copy.

The source format specifies structured range endpoints and inclusivity, but it
does not by itself establish a comparison algorithm for every vendor version.
Termivar therefore does not claim that the provider's semantics equal either
`numeric-dotted/v1` or `php-release-subset/v1`. With no explicit selector,
source semantics remain unresolved. With one selector, the result is explicitly
qualified as a Termivar calculation under the operator-selected rule. The
`1.0` versus `1.0.0` boundary remains an explicit regression case for this
distinction.

Only the complete endpoint value `*` is the supported unbounded sentinel;
`1.*` is an unsupported version spelling, not a glob. The selected profile is
used for both endpoint ordering and membership. A supported version in one
containing range can produce a qualified positive even when another range is
unsupported, but the report retains that partial range coverage. A negative
`outside` result requires every declared range to be supported and conclusively
outside. Unsupported ranges, missing or conflicting version evidence, reversed
bounds, and equal bounds made empty by an exclusive endpoint remain
indeterminate. Termivar does not swap, drop, pad, strip, or retry those values
under another comparator.

Source-declared patched versions remain advisory metadata and never establish
the installed patch state. Under an explicit profile, if a supported declared
patched version also falls inside a supported affected interval in the same
association, v5 reports
`source_patched_version_within_affected_range` and keeps the association
indeterminate. Unsupported patched-version spellings are retained verbatim as
source guidance; they are not retried under another profile or used to invent
affected bounds.

Reports identify the external format and mapping revision, preserve the
exact-input byte length and digest, and retain required notices for material
they display. V4 preserves its unresolved selected/unsupported accounting. V5
adds reconciled denominators for selected associations, decisive within/outside
relations, indeterminate associations, and evaluated/unsupported/invalid/
not-evaluated ranges, including qualified-positive partial coverage.

The additive `security.wordpress-review-audit/v6` shape is used when expanded
source-identity or V2/V3 resource-policy metadata is required. It retains the V4
or V5 comparison-policy meaning selected by the invocation and adds the actual
mapping and resource-policy IDs, accounted retained-import bytes, source identity
and mapping state for selected evaluations, collision metadata where applicable,
and the reconciled four-way identity totals. V6 also records exact
`projected_identity_limitations` and `unprojected_identity_limitations` counts.
At most 64 deterministically ordered `identity_limitations` detail rows are
expanded for structurally valid source identities that could not be represented
canonically. Their raw kind/slug, upstream identity, declared ranges/fix
information, and required attribution remain reviewable. The aggregate
unresolved count still covers the complete imported snapshot; rows outside the
detail projection are neither discarded from that accounting nor treated as
irrelevant or unaffected. Applicability and version comparison remain
explicitly not evaluated.
Historical audits v1 through v5
and their validation rules are unchanged. An unselected external comparator in
v6 therefore remains unresolved; the newer audit shape is not permission to
invent a comparison result.

Overlapping coverage qualifications are not added together as if they were
findings. These values identify the processed bytes and interpretation;
they do not authenticate the source, prove snapshot completeness, or establish
a collection timestamp. Source-declared `published` and `updated` values remain
distinct from collection time. A filesystem modification time is not substituted
for any of them.

The independently written
[`wordfence-v3` synthetic fixture](examples/wordpress-review/wordfence-v3/README.md)
records the public-schema-only expectations used by the parser and end-to-end
acceptance. It is not a live export, no provider credential was used, and this
does not establish compatibility with a complete current feed snapshot.

## Development acceptance evidence

The source tree keeps a separate, synthetic WordPress acceptance corpus under
`crates/termivar-scanner/tests/fixtures/wordpress_acceptance`. Its literal
expectations are maintained independently from the evaluator implementation,
and its reviewed and holdout inputs are labelled separately. The reviewed set
contains four records: one declared-data candidate, two missing-evidence
results, and one unsupported result. The holdout set contains two records: one
contradicted result and one missing-evidence result. These are conformance
denominators for the declared fixtures, not a detection-accuracy percentage.

The same acceptance layer covers missing inventory categories, must-use and
drop-in plugin rows, parent themes, and plugin/theme identities that share a
slug. A generated large-input case reads 4,096 synthetic external records and
selects exactly one relevant association while accounting for 4,095 deliberate
exclusions. It records byte and retained-data measurements plus non-contract
timing observations; it does not model or certify a complete provider feed.

A process-level feature-enabled test performs two assessments against the same
benign loopback origin, changes only declared local WordPress inputs, verifies
both report bundles, and compares them in both directions. The expected
component-version and advisory range/fix dimensions are literal test oracles.
The two scans must retain the same request trace, while Verify and Compare add
no target request. Existing CI executes that test natively on Linux, Windows,
and macOS. The current development four-platform curated release check also
builds WordPress through `release-bundle`, then exercises its synthetic saved
input/report path from each extracted native archive. Runtime opt-in remains
explicit, and the published alpha.2 archives retain their earlier WordPress-free
composition.

No actual Wordfence vendor export is committed to or relabelled as part of this
acceptance corpus. Public-schema synthetic cases exercise parser and policy
contracts, but by themselves do not establish current full-snapshot
compatibility, source authenticity, or complete provider coverage. Any
authorized private real-snapshot acceptance and process measurements are kept
as separately scoped task evidence without publishing the feed or its prose.
The repository's small curated WordPress-project example retains its separate
primary-source factual provenance; it is not relabelled as vendor-feed data.

### Linux resource acceptance measurements

The exact-head `WordPress Resource Acceptance` CI job builds the
feature-minimal `wordpress-review` CLI and its ignored resource probe with Rust
1.88 in release profile and a fresh runner-temporary Cargo target. It runs each
synthetic case in a fresh child process and records Linux `/usr/bin/time` peak
resident set size in KiB together with observed elapsed time, input bytes,
record/association/range counts, relevant-selection counts, retained-import
accounting, and output bytes.
The bounded artifact contains only
`wordpress-resource-acceptance.json` and
`wordpress-resource-acceptance.md`.

The synthetic matrix covers a no-input process baseline, a small input,
accepted distinct sparse inputs at 4,096, 16,384, 32,768, and 65,536 records,
an explicit retained-import rejection at 81,920 records, and a many-relevant-
records case. The 32,768- and 65,536-record cases exercise V2 and V3
respectively; their expected policies are independent literal oracles rather
than inferred from probe output. A separate valid single-record case between
512 KiB and the additive 768 KiB ceiling proves the enlarged per-record
envelope is accepted rather than testing only its upper rejection. Relevant
rows occur late in the sparse inputs
so a successful prefix parse cannot satisfy the oracle. Separate typed cases cover raw input,
individual record, individual field, collection and object-member limits,
retained-import limit-plus-one, malformed-tail, duplicate-identity, and
interrupted-read boundaries; these cases are not presented as process-memory
benchmarks.

Peak RSS is an operating-system observation for the measured child process,
not an exact Rust heap measurement or the configured 160 MiB retained-import
charge. Independent-process peaks are not subtracted to claim component memory,
and noisy elapsed timings are evidence from that runner rather than a product
deadline or performance guarantee. Inputs are generated synthetic data, not a
Wordfence export. Consequently the checked-in measurement does not authenticate
a source or establish that every allowed maximum-size combination or future
provider snapshot will be accepted.

| Acceptance surface | Status | Evidence boundary |
| --- | --- | --- |
| Saved plugin/theme/core inventories | Implemented and tested | Synthetic WP-CLI-shaped files; Termivar does not run WP-CLI |
| Declared Wordfence V3 Production input | Implemented and tested | Public regression data is synthetic; separately authorized private snapshot qualification does not redistribute vendor bytes or prose |
| Explicit external version interpretation | Implemented in development source | Operator-selected Termivar profile; source semantics remain `not_established` |
| Reviewed/holdout evaluator outcomes | Implemented and tested | Six fictional records with literal expected denominators |
| Cross-run semantic Report Compare | Implemented and tested | One benign exact-origin fixture; no remediation causality |
| Feature-enabled native CLI | Implemented and tested in CI | Linux, Windows, and macOS runners; not a fresh-machine certification |
| Linux process resource evidence | Measured in exact-head CI | Synthetic inputs and child-process peak RSS; not a heap cap or real-feed benchmark |
| Current development release bundle | Compiled Preview; explicit runtime opt-in | Untagged alpha.3 builds include `wordpress-review`; the default build and published alpha.2 archives do not |
| Private vendor-snapshot acceptance | Separately qualified task evidence | No vendor bytes, account, or API credential are committed; one accepted snapshot does not authenticate its source or guarantee future feeds |
| Live API retrieval | Unsupported | The assessment performs no Wordfence network request or key discovery |
| Exploit and impact validation | Unsupported | Both remain `not_performed` |

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
catalogue or explicitly selected interpretation rule. A contradicted result
does not establish that the installation is safe. A qualified external match
keeps any unsupported-range limitation visible. Missing or conflicting
versions, unknown prerequisites, unsupported or invalid ranges, and unresolved
source-comparison semantics remain limitations rather than disappearing from
the report.

Fixed or patched versions and remediation text are labelled
**source-declared remediation information**. They are guidance for the
operator's normal compatibility and update process, not an automatic update or
a verified local fix. The report states `exploit_execution=not_performed` and
`impact_validation=not_performed`; association counts are not added to the one
WordPress surface observation as vulnerability counts.

JSON retains the complete versioned audit contract and CSV retains its existing
bounded audit projection. Offline Verify checks the saved document and bundle
contract, not advisory truth. The matching development Report Compare reader
can add the semantic WordPress comparison described below; it remains a
comparison of supplied documents, not remediation proof.

## Offline WordPress comparison

When either supported input to `termivar report compare` contains a WordPress
audit, the output includes an optional `wordpress_review_comparison` section
with nested schema `termivar-wordpress-review-comparison/v1`. This is additive:
the outer `termivar-report-comparison/v1` schema and its four existing item
groups are unchanged. The section is absent when neither report has a
WordPress audit.

The required `--same-scope` flag remains only the operator's declaration that
the selected reports are comparable; it does not authenticate a site or prove
that both audits observed the same installation. Within that declared scope,
components match by kind and canonical slug. Native advisory records match by
`catalog.id`, upstream advisory ID, and component kind/slug. External records
from v4/v5 match by source namespace, upstream ID, and exact canonical component
kind/slug. V6 additionally preserves the raw source kind/slug in association
identity, so two different source spellings do not collapse merely because
they derive the same candidate canonical key. Titles, CVEs, array order, and
other display content do not replace those stable keys.

The section reports component evidence, advisory content, affected ranges,
source-declared fix/remediation, methodology, provenance, coverage, and
applicability changes as separate dimensions. It does not assign causality
between them. If one report has no WordPress audit, the result is
`not_compared` with `coverage_changed`; the available side is not treated as a
new vulnerability or a resolved condition. The same claim limit applies to an
advisory disappearance or applicability transition.

Supported `security.wordpress-review-audit/v1` through `/v7` inputs are
interpreted to the historical depth each contract actually contains; later
coverage or provenance fields are not invented for earlier versions. An exact
input SHA-256 identifies bytes, while semantic comparison uses validated typed
content. A byte change alone therefore does not establish a WordPress meaning
change, authenticity, or freshness. Compare imports the two saved reports and
does not rerun the scanner, WP-CLI, PHP, advisory retrieval, or any network
request.

For v5, a change in `comparison_policy`, `comparison_profile`, selection
basis, or source-assurance declaration is reported as a methodology change.
The same source record and component retain their stable identity across that
change. A transition between unresolved v4 and evaluated v5 is therefore not
labelled a newly introduced vulnerability or verified remediation.

For v6, changes to mapping revision, mapping state, collision metadata,
resource policy, retained-import accounting, or the four-way identity coverage
are likewise methodology or coverage changes. A candidate becoming ambiguous,
an unresolved association becoming mappable, or an expanded decoder accepting
more source rows is not automatically an installed-component change, a newly
found vulnerability, or remediation. The matching development Compare and
Verify readers validate v6 strictly without scanning, network access, or
granting imported data runtime authority. They recompute only document-internal
mapping, range, and profile consistency from the imported display data so
contradictory saved claims are rejected.

For v7, the required v1–v6 review basis continues to control those same
component and advisory checks. The wrapper adds the selected discovery policy,
candidate/source coverage, and exact attempt accounting as methodology and
coverage facts. An older binary that predates v7 cannot be assumed to read a
v7 document even though the underlying basis is historical.

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
audit, including v6. Development readers that know only v1 through v5 do not
silently reinterpret v6; they reject that unsupported audit version. The
already-published `v0.10.0-alpha.2` Compare and Verify importers predate all
WordPress audit fields and reject WordPress-extended assessment JSON; use the
matching development reader or a later release for those files. Neither offline
command starts a scan or adds network requests.

## Source and scope notes

The existing development references were reviewed on 2026-09-06. The pinned
PHP implementation reference for the comparison profiles was additionally
reviewed on 2026-09-07. The public-metadata discovery references were reviewed
on 2026-09-10:

- WordPress generator function reference:
  <https://developer.wordpress.org/reference/functions/get_the_generator/>
- WordPress REST API discovery relation:
  <https://developer.wordpress.org/rest-api/using-the-rest-api/discovery/>
- Current `get_rest_url()` implementation, including the no-pretty-permalink
  `index.php` form:
  <https://developer.wordpress.org/reference/functions/get_rest_url/>
- Theme main stylesheet and bounded file-header behavior:
  <https://developer.wordpress.org/themes/core-concepts/main-stylesheet/>
  and <https://developer.wordpress.org/reference/functions/get_file_data/>
- Plugin readme and Stable tag semantics:
  <https://developer.wordpress.org/plugins/wordpress-org/how-your-readme-txt-works/>
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
