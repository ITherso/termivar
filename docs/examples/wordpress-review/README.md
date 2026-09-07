# WordPress review input examples

These files demonstrate the bounded local input schemas for Termivar's
optional WordPress evidence review:

- `context.synthetic.json` is a fictional `example.test` operator declaration.
  It does not describe a scanned or real installation.
- `advisories.curated.json` contains one manually curated record from an
  official WordPress project advisory.
- `advisories.synthetic.json` contains fictional records for matched,
  contradicted, and unsupported-version examples. None alleges a real
  vulnerability.
- `context.profiles.synthetic.json` and
  `advisories.profiles.synthetic.json` are paired fictional fixtures for the
  explicit V2 comparison profiles. They do not describe a real installation or
  advisory.

The curated record is based on the official WordPress project advisory
`GHSA-fpp7-x2x2-2mjf`, retrieved 2026-09-06:
<https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-fpp7-x2x2-2mjf>.
The corresponding official security-release bulletin is
<https://wordpress.org/news/2026/07/wordpress-7-0-2-release/>.
The source explicitly lists affected versions `6.8.0` through `6.8.5`,
`6.9.0` through `6.9.4`, and `7.0.0` through `7.0.1`, with patched versions
`6.8.6`, `6.9.5`, and `7.0.2`. The example encodes exactly those three
half-open ranges; it does not infer an open-ended range or copy the advisory's
narrative.

The catalogue revision is `2026-09-06.1`. Its exact SHA-256 is recorded below
after generation. Treat the digest as an identifier for these bytes, not as a
signature or proof of source authenticity. To update the example, manually
review an official source, change the revision/retrieval date and factual
fields, then calculate and record a new digest. Never update the snapshot by
fetching data during a scan.

Exact `advisories.curated.json` SHA-256:
`403bfb7fa61d46cdfe62c12555b1743e5297bfecceaf670a5178705ab140a7ee`.

The `usage_basis` field states the narrow basis honestly: the example manually
extracts a few attributed factual identifiers and explicit version bounds. It
does not redistribute a bulk database or advisory narrative, and it does not
claim WPScan compatibility or coverage. WordPress software's GPL does not by
itself establish a blanket licence for advisory prose. WordPress is a
registered trademark of the WordPress Foundation; this independent example is
not endorsed by or affiliated with the WordPress project.

For a feature-enabled development binary, copy the fictional context to a
private temporary file and change its root to the exact already-running benign
loopback fixture root. Then use new private output paths:

```bash
termivar scan http://127.0.0.1:<fixture-port>/ \
  --profile web-review \
  --wordpress-review \
  --wordpress-context <edited-context.json> \
  --wordpress-advisories docs/examples/wordpress-review/advisories.curated.json \
  --report-dir assessment-wordpress
```

The example core declaration `6.9.4` falls within a source-declared range, but
it remains an operator declaration. A resulting candidate match remains audit
data and does not mint a `NeedsReview` item. It is not proof of the live
version, exploitability, impact, or absence of a backport. The scan does not
fetch the linked advisory or execute an exploit. Missing or unmatched catalogue
records never mean that no vulnerabilities exist.

When `context.synthetic.json` and `advisories.synthetic.json` are evaluated
together, the independently intended branches are:

| Fictional record | Intended decision basis |
| --- | --- |
| `SYNTHETIC-PLUGIN-MATCH-0001` | Declared `1.4.0` is in `[1.0.0, 2.0.0)` and the supplied activation prerequisite matches |
| `SYNTHETIC-PLUGIN-UNSUPPORTED-VERSION-0001` | The declared `2.4.0-beta1` is outside the numeric-dotted V1 profile and activation is unknown, so the result stays unsupported/indeterminate |
| `SYNTHETIC-THEME-CONTRADICTED-0001` | The declared version is in range, but supplied inactive state contradicts the record's active prerequisite |

These expected decisions are documentation oracles for fictional data. They do
not reproduce or predict any real WordPress vulnerability.

The V2 profile fixtures add these independently intended branches:

| Fictional record | Explicit profile | Intended decision basis |
| --- | --- | --- |
| `SYNTHETIC-BETA-NUMERIC-0001` | `numeric-dotted/v1` | Declared `2.4.0-beta1` is unsupported by the numeric-only profile, so the result remains indeterminate |
| `SYNTHETIC-BETA-PHP-SUBSET-0001` | `php-release-subset/v1` | The same declaration is within the explicit `[2.4.0-beta0, 2.4.0)` interval and its supplied activation prerequisite matches |
| `SYNTHETIC-TRAILING-ZERO-NUMERIC-0001` | `numeric-dotted/v1` | Declared `1.0` equals the inclusive `1.0.0` endpoint under V1 trailing-zero normalization |
| `SYNTHETIC-TRAILING-ZERO-PHP-SUBSET-0001` | `php-release-subset/v1` | Declared `1.0` sorts before the inclusive `1.0.0` endpoint because the PHP subset does not synthesize a release component |
| `SYNTHETIC-VENDOR-LABEL-UNSUPPORTED-0001` | `php-release-subset/v1` | The unknown `vendor1` label is unsupported rather than stripped or assigned a guessed rank |

These fixtures demonstrate data-selected methodology only. A
`candidate_match_on_declared_facts` result is not proof of an installed
vulnerability, exploitability, impact, or an absent backport. The scan still
performs no exploit execution or impact validation and profile selection adds
no target requests.
