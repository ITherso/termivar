# ADR 0017: Make the deterministic runtime the canonical scan command

- Status: Accepted
- Date: 2026-08-14
- Supersedes: ADR 0014's command-to-runtime mapping
- Retains: ADR 0015's platform-shell classification

## Context

ADR 0014 recorded the executable truth at the time: `venom scan` selected the
ordered direct-I/O phase runner and the deterministic decision runtime was a
separate command. That mapping changed when the CLI product boundary was made
fail-closed and deterministic by default. Leaving ADR 0014 as the current
command map would now contradict both source and user-facing help.

The two implementations remain distinct. Renaming them must not imply shared
accounting, claim semantics, or execution authority.

## Decision

- `venom scan <target>` is the canonical CLI entry point for the bounded
  `StandardWebDecisionRuntime` profile.
- `venom decision-scan` is a deprecated command alias for that exact same Clap
  command and execution function. The historical `decision-scan/v1` JSON schema
  name remains unchanged.
- The ordered phase runner is named `legacy-scan`, is absent from default
  builds, requires the `legacy-scanner` feature and an explicit acknowledgement,
  and reports partial heuristic observations rather than vulnerabilities.
- Optional API and proxy adapters stay feature-gated and are not part of the
  default CLI surface.
- The platform-shell classification from ADR 0015 remains useful; this record
  changes the command-to-runtime mapping from ADR 0014, not that classification.

The current executable map lives in
[`internals/runtime-map.md`](../internals/runtime-map.md).

## Consequences

- A default CLI invocation reaches the deterministic runtime; the legacy runner
  cannot be selected accidentally by the default binary.
- The compatibility alias cannot drift into a second behavior path.
- Documentation must call out `legacy-scan` wherever historical phases or their
  whole-run `Unmetered` accounting are discussed.
- ADR 0014 remains an immutable historical decision, but is no longer the
  current authority for CLI command mapping.

## Alternatives considered

- **Keep `scan` on the historical runner.** Rejected because it made the less
  bounded, heuristic path the product default.
- **Delete the compatibility alias immediately.** Rejected because the alias
  can preserve pre-1.0 command compatibility without preserving a second
  runtime path.
- **Rename the `decision-scan/v1` wire schema in place.** Rejected because a CLI
  command rename does not justify a breaking diagnostics-schema change.
