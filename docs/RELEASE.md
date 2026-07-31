# Release process

Venom follows Semantic Versioning. Pre-release identifiers such as `-alpha` communicate stability; they are part of the version, not a separate status string.

## Release gate

- workspace version and CLI output agree;
- changelog entry is complete;
- formatting, lint, unit, integration, security, and compatibility checks pass;
- benchmark results are reproducible and do not contain unsupported claims;
- security advisories and dependency findings are triaged;
- supported-version table is current;
- tag, release title, and artifacts use the same version.

## Release notes template

```markdown
# Venom vX.Y.Z

## Added

## Changed

## Fixed

## Security

## Upgrade notes

## Verification
```

Omit an empty category rather than adding filler. Security fixes should link to the published advisory after coordinated disclosure. Checksums and provenance should accompany downloadable artifacts.

## Alpha release

For `0.9.0-alpha`, do not use “production-ready,” completion percentages, or unverified performance numbers. Clearly identify unstable APIs, disabled legacy fixtures, and the absence of an independent audit.
