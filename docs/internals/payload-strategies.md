# Payload strategy boundary

Venom does not make the planner a payload generator. The planner selects a
semantic action and, when required, an exact strategy ID and revision. A native
capability executor is the only component that may resolve that reference and
derive one bounded artifact.

> Current maturity: this release ships the reference, derivation, propagation,
> and exact-support negotiation contracts. No standard profile registers a
> strategy-aware production executor yet, so the host does not currently
> materialize or dispatch payload artifacts in normal runtime execution.

```text
Evidence -> Hypothesis -> AttackAction
                            |
                            v
                 PayloadStrategyRef (ID + revision)
                            |
                            v
                  DecisionExecutionRequest
                            |
                            v
                 Native capability executor
                            |
                    PayloadStrategy
                            |
              one Control or Candidate artifact
                            |
                            v
              host-owned accounting broker
```

## Contract

`PayloadStrategy::derive_one` is deliberately synchronous and pure. The same
strategy reference, role, seed, and limits must yield the same bytes and digest.
The contract module cannot import clocks, randomness, knowledge state, runtime
state, or transport clients; `cargo xtask architecture` enforces this boundary.
Implementations may live in capability modules, so determinism is also a
trusted implementation invariant. Every native implementation must add and
pass repeat/concurrency conformance tests before registration in a standard
profile.

A conforming future native executor must produce one artifact per turn:

- passive evidence collection requests a `Control` artifact;
- explicit active verification requests a `Candidate` artifact.

This aligns differential work with the existing evidence transaction boundary.
A committed control observation stays auditable if the candidate is later
blocked by policy, exceeds a budget, times out, or fails verification.

## Limits and redaction

The default seed and output ceiling is 4 KiB and the compiled hard ceiling is
64 KiB. A zero limit is valid and fails closed. Strategy output is validated a
second time by `PayloadStrategyRegistry`.

`PayloadSeed` and `PayloadArtifact` are intentionally not serializable. Their
debug representations show only `<redacted>`, byte length, and digest. Use
`PayloadArtifact::receipt()` for audit output; it contains:

- strategy ID and revision;
- control/candidate role;
- byte length;
- SHA-256 digest.

It never contains the raw seed or derived bytes.

The digest provides replay provenance, not confidentiality. Small or
predictable payloads can be recovered with a dictionary attack against an
unkeyed SHA-256 value. Treat receipts as pseudonymous security telemetry and do
not publish them when the underlying payload space is sensitive.

## Transport requirement

Resolving a strategy does not authorize network I/O. A native executor must use
the host-owned request broker. The broker atomically charges request count,
buffered request-body bytes, active verification, and transport-delivered
response-body bytes while bounding the retained prefix.
Opaque streaming bodies whose length cannot be charged are rejected before
dispatch.

The legacy plugin bridge and ordered phase runner do not inherit this guarantee.
Do not attach strategy-aware actions to them. The classic directory fuzzer is
available only through the explicit `--legacy-directory-fuzz` CLI option while
its broker migration remains pending.

## Differential analysis

Payload derivation and response comparison are separate responsibilities. JSON
visibility differences use `ApiVisibilityComparator` and its versioned profiled
envelope. An empty path summary is not treated as equivalence: status-only or
structural differences can be classified as
`DifferenceWithoutPathSummary`. Visibility differences remain review signals,
not automatic vulnerability verdicts.
