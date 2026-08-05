# ADR 0014: Consolidate runtime truth into three named surfaces

- Status: In review
- Date: 2026-08-05
- Depends on: ADR 0004 (reasoning/runtime boundary)

## Context

Venom accumulated documentation and scaffolding that described capabilities as if
they were part of one coherent runtime. In reality the repository has **three
distinct runtime surfaces** that do not share an execution path, and several
described capabilities were not wired into any runnable path at all. This drift
made it easy for a reader — or a scanner — to assume a feature runs when it does
not.

The consolidation work (splitting the prior mega-change into reviewed slices)
established the actual executable state:

- `venom scan` uses `ScanContext -> ScanRunner -> ordered phases/*` and performs
  **legacy direct I/O** outside `StandardWebDecisionRuntime` and `RuntimeBudget`;
  the CLI prints a warning to that effect.
- `StandardWebDecisionRuntime` is a separate, budget-bounded decision runtime,
  exercised by tests and the `decision_scan` host, but **not** the default CLI
  path.
- A "platform shell" of feature-gated and library modules surrounds those two
  runtimes with varying levels of support.

## Decision

Treat these three surfaces as the canonical description of the runtime, and keep
documentation aligned to what actually executes:

1. **Default CLI runtime (legacy direct I/O)** — surface A.
2. **Deterministic decision runtime** (`StandardWebDecisionRuntime`) — surface B,
   which exists and is tested but is not the default CLI path.
3. **Platform shell** — surface C, where runtime-critical module groups are
   classified along independent axes (build availability, execution
   participation, default-scan participation, support status). ADR 0015 defines
   that model; the runtime map classifies groups, not every `pub mod`.

The authoritative, verifiable map lives in
[`internals/runtime-map.md`](../internals/runtime-map.md). Documentation must not
claim a capability runs on a surface where it does not, and must not present
unimplemented capabilities (Relation Engine, Planes, Knowledge Graph, Machine
Scanner, a bound API listener, a supported MITM proxy, cloud deployment) as
implemented. Semantic Phase 1.5 is documented as implemented and tested but not
yet wired into the default CLI runtime. The unsupported deployment status
(ADR/PR-F outcome) is reflected rather than hidden.

## Consequences

- Readers get an honest, surface-scoped view; "compiled" is distinguished from
  "executed", and "tested runtime" from "default runtime".
- Future capability work states which surface it targets and whether it is wired
  into the default CLI path.
- Numeric inventories are only published with a snapshot commit and an exact
  generating command, so counts cannot silently drift.
- This ADR is documentation-only: it changes no Rust, Cargo, CI, infrastructure,
  runtime, or scanner behavior.

## Alternatives considered

- **Keep a single "runtime" narrative.** Rejected: it is the source of the drift;
  it conflates the legacy CLI path with the deterministic decision runtime.
- **Delete the decision runtime docs until it becomes the default path.**
  Rejected: surface B is real and tested; hiding it is as inaccurate as
  over-claiming it. Labelling it "not the default path" is the honest middle.
