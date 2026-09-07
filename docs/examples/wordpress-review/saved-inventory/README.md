# Synthetic saved WordPress inventory

These small files exercise Termivar's bounded saved-inventory input. They were
written as synthetic fixtures; they were not captured from a real WordPress
installation and do not allege a vulnerability, product installation, or
remediation state.

For an installation the operator is authorized to inspect, create the same
narrow projections with WP-CLI outside Termivar:

```bash
wp plugin list --fields=name,status,version --format=json > wordpress-plugins.json
wp theme list --fields=name,status,version --format=json > wordpress-themes.json
wp core version > wordpress-core-version.txt
```

Termivar consumes already-saved files and never invokes WP-CLI or PHP. To use
this fictional set with an already-running, repository-owned benign fixture,
substitute its exact numeric-loopback origin and run a feature-enabled
development binary:

```bash
termivar scan http://127.0.0.1:<fixture-port>/ \
  --profile web-review \
  --wordpress-review \
  --wordpress-plugins-json docs/examples/wordpress-review/saved-inventory/plugins.synthetic.json \
  --wordpress-themes-json docs/examples/wordpress-review/saved-inventory/themes.synthetic.json \
  --wordpress-core-version-file docs/examples/wordpress-review/saved-inventory/core-version.synthetic.txt \
  --wordpress-advisories docs/examples/wordpress-review/advisories.profiles.synthetic.json \
  --report-dir assessment-wordpress-inventory
```

The three input categories are independent. A category not supplied to the
command remains unknown, not empty; a supplied empty array is not authenticated
proof of absence. The files are operator-supplied declarations. Their fixed
class, exact byte length, and SHA-256 identify the bytes placed into the review,
but do not authenticate WP-CLI, the target, or inventory completeness. Input
paths are not retained in the assessment.

The fixture demonstrates the accepted status vocabulary:

- plugins: `active`, `inactive`, `active-network`, `must-use`, and `dropin`;
- themes: `active`, `inactive`, and `parent`.

Only `active`, `inactive`, and plugin `active-network` establish their matching
typed activation states. Must-use and parent classifications do not synthesize a
normal activation state. The synthetic drop-in filename cannot serve as a
canonical catalogue slug, so it appears only as a bounded limitation and is not
evaluated as an advisory component.

The inputs share the existing 1 MiB and 256-entry inventory ceilings. The final
file component is opened without following links and the opened handle must be
regular; parent directories remain trusted. Termivar performs no WP-CLI command
and inventory interpretation adds no network request to the assessment.

The raw `2.4.0-beta1` and core prerelease strings are retained as supplied.
Their interpretation comes only from an advisory record's comparison profile:
`numeric-dotted/v1` leaves a suffix-bearing value unsupported, while the
explicit `php-release-subset/v1` can interpret its bounded grammar. A profile
result remains declared-data audit information, not proof of a live version or
confirmed vulnerability.
