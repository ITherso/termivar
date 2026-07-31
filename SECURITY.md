# Security Policy

Venom is security-testing software. Its alpha releases may contain defects that affect confidentiality, integrity, availability, or scan accuracy. Use Venom only on systems you own or are explicitly authorized to test.

## Supported versions

| Version | Supported | Notes |
| --- | --- | --- |
| `main` | Yes | Security fixes land here first |
| `0.9.0-alpha` | Yes | Best-effort support until the next pre-release |
| Earlier snapshots | No | Upgrade before reporting a defect |

Support means the maintainers will assess valid reports; it does not imply a production-readiness guarantee.

## Responsible disclosure

Do not open a public issue for a suspected vulnerability.

Use [GitHub private vulnerability reporting](https://github.com/ITherso/venom/security/advisories/new). Include:

- affected version or commit;
- affected component and configuration;
- impact and realistic attack scenario;
- minimal reproduction or proof of concept;
- suggested mitigation, if known;
- whether you want public credit.

Avoid accessing data that is not yours, disrupting third-party services, or testing beyond the minimum needed to demonstrate impact.

## PGP

The project does not currently publish a PGP key. Use GitHub's private vulnerability reporting channel, which keeps the report within the repository's security advisory workflow. A future project key and fingerprint will be published here before encrypted email reporting is accepted.

## Response targets

These are targets, not contractual guarantees.

| Stage | Target |
| --- | --- |
| Automated receipt | Immediate |
| Human acknowledgement | 2 business days |
| Initial severity assessment | 5 business days |
| Remediation plan for confirmed critical issues | 7 business days |
| Coordinated disclosure | Normally within 90 days |

Complex issues, incomplete reports, maintainer availability, or upstream dependencies may affect timing. We will communicate material delays through the private advisory.

## CVE process

1. The maintainers reproduce and validate the report.
2. Severity and affected versions are agreed with the reporter where practical.
3. A fix and regression test are prepared privately.
4. A GitHub Security Advisory is drafted. A CVE is requested when the issue meets CVE assignment criteria.
5. Supported branches and release notes are updated.
6. The advisory is published after a fix is available or at the coordinated disclosure deadline.

Duplicate reports are handled in order of the first complete, reproducible submission.

## Credits and Hall of Fame

Researchers with a confirmed report may be credited in the advisory and in this section, with their consent. Anonymous credit is also available.

No researchers are listed yet.

## Scope notes

Reports about the following are particularly useful:

- proxy certificate or key handling;
- authentication and authorization bypass;
- unsafe Lua or plugin sandbox escape;
- request smuggling or parser differentials;
- secret exposure in logs or reports;
- malicious scan target responses causing code execution, denial of service, or data exposure;
- dependency vulnerabilities with a demonstrated impact on Venom.

General hardening suggestions, unsupported-version bugs, and scan findings against third-party targets should use normal project discussions after removing sensitive data.
