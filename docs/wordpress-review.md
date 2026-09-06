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
conflicting declarations remain conflicting rather than using last-write-wins.

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
`network_active`. It is a small typed selection, not an importer for arbitrary
raw WP-CLI output, and Termivar never invokes WP-CLI or PHP.

The complete context file is limited to 1 MiB. See
[`docs/examples/wordpress-review/context.synthetic.json`](examples/wordpress-review/context.synthetic.json)
for a deliberately fictional declaration.

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

The evaluator checks component identity before version intervals and reports
version relation and each prerequisite separately. It does not infer an open
lower bound merely because a bulletin names a fixed version. Disjoint
maintained branches remain separate. Unsupported prerequisites remain
unevaluated rather than being discarded. Prerequisites are conjunctive: an
outside declared range or a supported prerequisite contradicted by supplied
facts makes the summary contradicted even when another prerequisite is
unsupported; absent a contradiction, unsupported evidence remains
indeterminate rather than becoming a match.

The example directory contains two catalogue types:

- [`advisories.curated.json`](examples/wordpress-review/advisories.curated.json)
  is one manually curated factual record from an official WordPress project
  advisory. It is a small example, not a vulnerability feed.
- [`advisories.synthetic.json`](examples/wordpress-review/advisories.synthetic.json)
  uses unmistakably fictional component and record identities to exercise
  matched, contradicted, and unsupported-version decisions. These are not
  alleged vulnerabilities.

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

Development references were reviewed on 2026-09-06:

- WordPress generator function reference:
  <https://developer.wordpress.org/reference/functions/get_the_generator/>
- WP-CLI plugin inventory fields and states:
  <https://developer.wordpress.org/cli/commands/plugin/list/>
- PHP version comparison behavior (broader than Termivar's V1 profile):
  <https://www.php.net/manual/en/function.version-compare.php>
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
