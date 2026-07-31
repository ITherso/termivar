# ADR 0001: Use a Cargo workspace with inward dependencies

- Status: Accepted
- Date: 2026-07-31

## Context

Venom has separate command-line, API, proxy, scanner, and shared-contract concerns. A single package would make transport and product policy easy to import into scanning logic and would make independent testing difficult.

## Decision

Use a Cargo workspace. Transport-neutral data, events, errors, and models belong in `venom-core`. Execution behavior belongs in `venom-scanner`. API, proxy, CLI, web, and future product layers depend inward and are never dependencies of core or scanner crates.

Workspace dependency cycles are release blockers. The CLI is the composition root for the shipped application, while third-party hosts may compose scanner contracts directly.

## Consequences

- Crate boundaries are visible in Cargo metadata and reviewable in dependency graphs.
- Shared types must be deliberately small and transport-neutral.
- Cross-cutting features sometimes require a contract in core and behavior in a higher crate.
- Additional crates increase workspace build coordination but reduce architectural coupling.

## Alternatives considered

- One monolithic crate: rejected because boundaries would be conventional rather than enforced.
- One crate per phase: rejected because it would create excessive packaging and versioning overhead during alpha.
