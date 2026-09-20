# Local reconnaissance snapshot import

`recon-snapshot-import` is a non-default, development-only CLI/scanner feature.
It adds one explicit input to the existing `web-review` assessment:

```text
termivar scan https://owned.example/ --profile web-review \
  --recon-snapshot recon-snapshot.json --report-dir assessment-recon
```

The input is a finite, inert reference snapshot. It does not create scan
subjects, extend target scope, mint broker permits, schedule requests, or
produce assessment items/findings. Imported names, addresses, banners, and
labels remain source-qualified hypotheses for operator review.

## Input contract

V1 uses schema `security.recon-snapshot/v1` and accepts one explicitly named
regular local JSON file. The CLI applies the same local-path and final-component
no-follow protections as other hardened local inputs, reads it once, and does
not retain the pathname in the product audit.

The root declares a snapshot identity/revision, sources, and records. Every
record references one or more declared sources. Supported records are limited
to:

- certificate-transparency name observations;
- historical DNS name/address associations;
- structured service-banner product hints; and
- reputation labels.

Source metadata includes its namespace/revision, declared provider and observed
times, collection method, completeness, origin, and operator-declared rights
posture. These declarations are data; Termivar does not authenticate them.
The input must not contain secrets: accepted source metadata and hypotheses are
intentionally reproduced in the assessment audit. Review the generated report
and its sharing destination before distributing a bundle.

The parser rejects duplicate JSON keys, unknown fields, duplicate source or
record identities, unresolved or repeated source references, invalid names,
addresses or ports, malformed UTF-8/JSON, and unsupported schema or enum values.
The initial hard limits are:

- 1 MiB exact input bytes;
- 1,024 sources;
- 1,024 records;
- 4,096 record-to-source references; and
- 4 MiB accounted prepared lookup-index data.

These are ceilings, not completeness promises. Existing smaller report and
process limits continue to apply.

## Network and authority boundary

The snapshot is loaded and fully validated before report-output reservation,
credential acquisition, runtime construction, or target traffic. It is attached
only after the ordinary assessment has completed. Neither the parser nor the
audit owns a network client.

Import adds exactly zero target requests and zero provider requests. It never
contacts a host named by a record, retrieves a source, validates a banner or
reputation label, follows a URL, decompresses an archive, or searches for other
files. A CT name does not prove current DNS ownership or authorization to scan;
a historical address does not authorize a shared-host tenant.

## Report meaning

The optional `security.recon-snapshot-import-audit/v1` section records the exact
input byte length and SHA-256 separately from declared provenance, bounded
source/record/reference counts, prepared-data accounting, and the admitted
source-qualified hypotheses. It also records that the import grants no scan
authority and that source authentication, asset ownership, current reachability,
vulnerability, and impact were not established.

The digest identifies the supplied bytes; it is not a signature, source
authentication, rights verification, freshness proof, or completeness proof.
The source file itself is never copied into a report bundle.

Offline Verify checks bundle bytes and the supported saved schema, not whether
the source statements are true. Compare reports snapshot/source changes,
coverage/accounting changes, and hypothesis changes as imported-context changes.
It does not describe an added or removed hostname as a target change,
vulnerability, or remediation.

The feature is outside `default`, the seven-member `release-bundle`, and the
published `v0.10.0-alpha.2` archives. Live provider adapters are a later,
separately authorized S10 slice; they are not part of V1 import.
