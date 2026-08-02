# ADR 0004: Keep deterministic reasoning inward of execution and runtime

- Status: Accepted
- Date: 2026-08-02

## Context

The alpha decision engine is evolving inside `venom-scanner` while its public
contracts are still moving. Splitting a `venom-reasoning` crate now would make
experimentation expensive, but leaving module direction implicit would allow
planner, rule, verification, and experience code to accumulate HTTP clients,
executor details, and runtime policy. That would recreate a scanner monolith
and make a later extraction substantially harder.

One reverse edge already demonstrated the risk: the transport-neutral standard
web verifier obtained its semantic action set from the HTTP executor profile.

## Decision

Until the APIs stabilize enough for a crate extraction, the following inward
dependency direction is mandatory:

```text
venom-core
    ^
knowledge / rules / experience / semantic action contracts
    ^
planning / verification / deterministic domain profiles
    ^
scanner runtime / HTTP execution / plugins / composition
```

In particular:

- planner code does not import HTTP, executor, plugin, or runtime modules;
- reasoning rules do not import planner or execution implementations;
- verifiers consume snapshots and evidence but never a network client;
- experience records outcomes without importing planner implementations;
- semantic profiles share action identities through `web_actions`, not through
  an executor registry or HTTP profile.

`cargo xtask architecture` is the executable policy. It validates Cargo
workspace edges with locked package metadata, checks protected production modules
through the Rust AST, rejects ambiguous crate-root re-export imports in those
modules, requires canonical attribute-free protected-module declarations in
`lib.rs`, prevents local bindings from shadowing approved external roots, and
compiles `venom-scanner` without default features. CI and the local release
preflight run the same command.

## Consequences

- Direction violations fail with the source module and forbidden dependency.
- Protected modules use canonical `crate::<module>` imports so ownership is
  visible to review and tooling.
- Protected module and external-crate roots cannot be redirected through
  `lib.rs` facades, conditional wiring, attributes, glob imports, or item macros.
- New workspace crates and new protected-module dependencies require an
  intentional policy and ADR review.
- HTTP execution remains replaceable without changing deterministic verifier
  contracts.
- The AST check is a temporary module-level fence, not compiler name
  resolution; a dedicated crate remains the stronger long-term boundary.

## Alternatives considered

- Extract `venom-reasoning` immediately: deferred while alpha APIs and profile
  boundaries are still changing.
- Rely on code review and documentation: rejected because the first reverse
  edge was valid Rust and easy to miss.
- Parse `cargo tree` and grep source text: rejected because both formats are
  brittle and can confuse comments or aliases with actual Rust dependencies.
