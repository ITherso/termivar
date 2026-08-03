# Compliance-oriented capabilities

Venom v0.9.0-alpha provides Preview data models that can help an integrator
organize compliance-oriented evidence. Venom is not certified, independently
audited, or a substitute for legal, privacy, or assurance work. Whether a
deployment meets a law, regulation, contractual obligation, or control
framework depends on the entire deployed system and the operating
organization—not on this repository alone.

## Capability and evidence matrix

| Area | What exists in this release | What it does not establish |
| --- | --- | --- |
| Framework labels | Serializable identifiers for GDPR, HIPAA, SOC 2, and PCI DSS | An official control catalog, validated control mapping, legal interpretation, or framework approval |
| Requirements | Caller-supplied requirement and control records | That a requirement is complete, current, applicable, or satisfied |
| Assessments | In-memory assessment records and arithmetic over caller-supplied control counts | A legal compliance determination, attestation, audit opinion, or calibrated assurance score |
| Reports | In-memory report records and score history | An auditor-ready report, signed evidence package, or regulator submission |
| Audit events | Process-local event records with basic filtering | Durable, immutable, complete, access-controlled, or retention-enforced audit logging |
| Data classification | Metadata records and queries for caller-declared classifications and encryption flags | Encryption, key management, data discovery, access control, deletion, or retention enforcement |
| Repository controls | CI definitions for tests and security tooling | A passing result for an unverified commit, production safety, certification, or independent review |

The built-in compliance module is therefore a reporting and integration model,
not a compliance engine. Its `is_compliant` helper applies a local numeric
threshold to supplied counts; applications must not present that value as a
legal or certification decision.

## Current assurance status

| Standard or assurance activity | Repository status |
| --- | --- |
| SOC 2 Type I or Type II | No attestation claimed |
| ISO/IEC 27001 | No certification claimed |
| GDPR | No deployment-specific legal assessment claimed |
| HIPAA | No compliance determination or Business Associate Agreement claimed |
| PCI DSS | No ROC, AOC, or self-assessment validation claimed |
| Independent penetration test | No completed external test report published |
| Independent source-code security audit | Not completed |
| Availability or vulnerability-response SLA | None guaranteed by this repository |

No auditor, certification date, penetration-test result, code-coverage
percentage, vulnerability count, privacy-policy URL, DPO, or service-level
response time should be inferred unless separate, verifiable evidence is
published for the applicable release and deployment.

## Repository evidence

The repository configures engineering checks such as Rust dependency policy,
static analysis, bounded fuzz campaigns, tests, and release builds. These
checks can produce useful point-in-time evidence for a review. They have
important limits:

- configured automation is not proof that a particular commit passed;
- a passing scan only describes its declared tool, inputs, rules, and time;
- absence of a reported finding does not prove absence of vulnerabilities;
- test, fuzz, benchmark, and coverage artifacts are not independent audits;
- repository controls do not assess deployment configuration, personnel,
  business processes, vendors, or legal obligations.

See [Repository health](repository-health.md) for the configured controls and
known gaps, [Code quality](CODE_QUALITY.md) for the local verification commands,
and [Security policy](https://github.com/ITherso/venom/blob/main/SECURITY.md) for
private vulnerability reporting.

## Using the Preview models responsibly

An integrator that uses the compliance module should:

1. maintain its own versioned and reviewed control catalog;
2. record the source, scope, owner, time, and provenance of every evidence item;
3. store audit evidence in a deployment-owned durable and access-controlled
   system;
4. distinguish observed facts from caller-entered assertions and calculated
   scores;
5. label generated output as Preview and subject to human review; and
6. obtain qualified legal, privacy, and assurance advice for the target
   jurisdiction and deployment.

Certification or compliance claims belong to the organization operating a
specific system and must be supported by the appropriate independent evidence.
