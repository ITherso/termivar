# Offline report comparison example

This directory is a labelled document-processing fixture for
`termivar report compare`. It is **not** a pair of real assessments and does
not allege that a target changed. The two inputs were derived from the public,
credential-free first-use document solely to exercise the four comparison
groups with independently selected expected counts.

The example was generated with development package version
`0.10.0-alpha.2`. Exact source and binary identity, input/output hashes, and the
generation command are recorded in [`provenance.json`](provenance.json).

<div class="tmv-example-actions" role="group" aria-label="Report comparison example files">
  <a class="tmv-button tmv-button-primary" href="comparison.html">Open the interactive comparison</a>
  <a class="tmv-button tmv-example-secondary" href="comparison.json">View comparison JSON</a>
  <a class="tmv-button tmv-example-secondary" href="before.json">Before fixture</a>
  <a class="tmv-button tmv-example-secondary" href="after.json">After fixture</a>
</div>

Expected groups:

| Group | Count | Fixture meaning |
| --- | ---: | --- |
| `only_in_after` | 1 | A synthetic identity exists only in `after.json` |
| `only_in_before` | 1 | A different synthetic identity exists only in `before.json` |
| `changed` | 1 | One shared identity has a deliberately edited display summary |
| `unchanged` | 1 | One shared identity has equal comparable content |

The generated comparison summary is therefore:

```text
only_in_after:  1
only_in_before: 1
changed:        1
unchanged:      1
```

Run from the repository root:

```bash
termivar report compare \
  --before docs/examples/report-compare/before.json \
  --after docs/examples/report-compare/after.json \
  --same-scope

termivar report compare \
  --before docs/examples/report-compare/before.json \
  --after docs/examples/report-compare/after.json \
  --same-scope \
  --format json \
  --output comparison.json

termivar report compare \
  --before docs/examples/report-compare/before.json \
  --after docs/examples/report-compare/after.json \
  --same-scope \
  --format html \
  --output comparison.html
```

The checked-in output files are the actual CLI results for those fixture inputs.
Use a new destination for another run: the command intentionally refuses to
replace an existing output. The before/after SHA-256 values in the comparison
identify supplied bytes; they do not authenticate a source or prove equivalent
assessment coverage. In particular, only-in-before is not verified remediation.
