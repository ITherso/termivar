# Runtime truth remediation closure

This record closes the remediation that began with the historical
[runtime-truth audit](runtime-truth-remediation.md). It does not rewrite that
baseline. The implementation evidence below was reviewed at
`df19f00ea2171cd8486a6256cb318755d063fb47`; the documentation-only closure
commit follows that code and coverage-enforcement head.

The closure preserves these product boundaries:

- an observation is not a vulnerability;
- action success is not vulnerability confirmation;
- same-origin transport policy is not authorization;
- payload delivery is not evidence that a vulnerability exists;
- missing evidence in a bounded sample is not evidence of absence;
- incomplete execution is not empty success; and
- a `KnowledgeOnly` objective has no hypothesis-transition authority.

## Dispositions

- **Fixed** means the defective behavior has a bounded, tested replacement.
- **Quarantined** means the surface remains available only behind an explicit
  compatibility, host-library, or inert non-product distribution boundary and
  does not participate in the default product.
- **Removed** means the misleading executable surface is absent and guarded
  against accidental reintroduction.
- **Deferred** means the repository explicitly does not implement the claimed
  capability; a future implementation needs a new reviewed contract.

## Product and execution truth

### Split-brain CLI

**Original problem.** `venom scan` used the historical ordered runner while
`decision-scan` alone used the deterministic runtime, exposing two materially
different scanner products.

**Resolution: Fixed.** `crates/venom-cli/src/main.rs` defines
`decision-scan` as a visible alias of `Scan` and routes both spellings through
`decision_scan::run_decision_scan`. The historical runner is separately
compiled behind `legacy-scanner` and requires explicit acknowledgement.

**Authority and proof.** ADR
[0017](../adr/0017-make-deterministic-scan-the-default.md); alias and feature
tests in `crates/venom-cli/src/main.rs` and
`crates/venom-cli/tests/decision_scan_cli.rs`; default-feature and module gates
in `xtask/src/architecture/platform.rs`.

**Remaining caveat.** Legacy compatibility code still exists, but the default
runtime never invokes it.

### Legacy completion truth

**Original problem.** Phase errors, panics, timeouts, cancellation, or partial
execution could collapse into an empty-looking successful run, while raw
finding prose looked more authoritative than its evidence.

**Resolution: Fixed.** `crates/venom-scanner/src/runner.rs` records typed phase
states, checkpoint rollback, explicit skips and accounting, and
`Complete`/`Partial`/`Failed`/`Cancelled` terminal status in `venom-run/v1`.
Unverified legacy prose is projected as unresolved `Unknown` rather than a
confirmed result.

**Authority and proof.** ADRs [0017](../adr/0017-make-deterministic-scan-the-default.md)
and [0018](../adr/0018-bound-legacy-verification-authority.md); runner tests for
failure, panic, budget exhaustion, timeout, cancellation, rollback, and partial
completion; completion-laundering gate in
`xtask/src/architecture/source_hygiene.rs`.

**Remaining caveat.** Phase one and custom legacy extensions may still perform
direct I/O, so whole-run request/body accounting remains explicitly
`Unmetered`.

### Crawler

**Original problem.** Legacy discovery did not have one explicit exact-origin,
bounded, deterministic traversal authority.

**Resolution: Fixed.** The replacement remains within the quarantined legacy
surface.
`crates/venom-scanner/src/legacy_discovery.rs` and `phase2_crawl.rs` implement a
shared exact-origin authority, stable breadth-first traversal, canonical URL
handling, finite HTML/form-name extraction, and atomic evidence commit.

**Authority and proof.** ADR
[0016](../adr/0016-bound-legacy-discovery-authority.md); local-fixture tests in
`phase2_crawl.rs` cover relative/absolute links, forms, malformed input,
cycles, canonicalization, cross-origin rejection, cancellation, and caps;
transport ownership is guarded by `xtask/src/architecture/transport.rs`.

**Remaining caveat.** The default deterministic scanner is still a
single-resource runtime. Legacy crawling is not silently composed into it.

### Soft-404 handling

**Original problem.** A status or body-marker difference could be treated as a
real discovered route without proving that it differed from wildcard behavior.

**Resolution: Fixed.** The replacement remains within the quarantined legacy
surface.
`crates/venom-scanner/src/phases/phase3_fuzzer.rs` uses two stable same-shape
controls, bounded normalized signatures, sequential candidates, and atomic
informational evidence.

**Authority and proof.** ADR [0016](../adr/0016-bound-legacy-discovery-authority.md);
phase tests cover wildcard and custom soft-404 responses, redirects, distinct
protected routes, truncation, echo scrubbing, cancellation, and budget
exhaustion; the migrated transport seam is architecture-gated.

**Remaining caveat.** A bounded negative sample is knowledge about that sample,
not proof that a route or vulnerability is absent.

### Parameter discovery

**Original problem.** One reflected marker could be presented as parameter
acceptance or vulnerability evidence.

**Resolution: Fixed.** The replacement remains within the quarantined legacy
surface.
`crates/venom-scanner/src/phases/phase4_param.rs` requires a matched baseline,
unknown control, candidate, and replay; rejects pre-existing markers and
truncation; omits generated probe values from findings and their public subject;
and emits informational evidence only.

**Authority and proof.** ADR [0016](../adr/0016-bound-legacy-discovery-authority.md);
phase tests cover positive and negative differentials, pre-existing markers,
replay failure, known parameters, cancellation, and budget exhaustion;
`xtask/src/architecture/transport.rs` pins the shared authority.

**Remaining caveat.** The observation does not establish exploitability. The
legacy canonical discovery state can retain the original endpoint query, including
pre-existing values; callers must not seed it with secret-bearing URLs.

## Legacy claim correction

### SQL behavior

**Original problem.** A quote followed by an error, status 500, or one delay
could be labelled SQL injection.

**Resolution: Fixed.** The capability remains quarantined.
`crates/venom-scanner/src/phases/phase5_sqli.rs` uses case-correlated
baseline/control/candidate/replay observations, alternating repeated timing
samples, and explicit error differentials. Only verifier-owned,
`KnowledgeOnly` `NeedsReview` is possible.

**Authority and proof.** ADR [0018](../adr/0018-bound-legacy-verification-authority.md);
tests reject a single 500, generic syntax, and one timing effect and exercise
bounded reproducible review evidence; claim-language and broker gates live in
`xtask/src/architecture/transport.rs`.

**Remaining caveat.** The legacy review does not confirm SQL injection and
performs no destructive SQL, writes, extraction, or authentication bypass.

### XSS reflection

**Original problem.** Marker reflection could be labelled confirmed XSS.

**Resolution: Fixed.** The capability remains quarantined.
`crates/venom-scanner/src/phases/phase6_xss.rs` uses an exact benign nonce with
baseline/candidate/replay correlation and rejects baseline, truncated, and
non-replayed matches. Its maximum outcome is informational `Unknown`.

**Authority and proof.** ADR [0018](../adr/0018-bound-legacy-verification-authority.md);
phase and runner tests prove exact reflection remains non-confirming; the
architecture gate rejects confirmation/vulnerability language in migrated
legacy verifiers.

**Remaining caveat.** No browser-execution verifier exists, so Venom cannot
confirm XSS.

### SSTI arithmetic

**Original problem.** A constant `49` or reflected payload could imply template
execution.

**Resolution: Fixed.** The capability remains quarantined.
`crates/venom-scanner/src/phases/phase7_ssti.rs` derives bounded variable
operands and requires control/candidate/replay plus the exact expected
arithmetic result absent from the control. Only verifier-owned,
`KnowledgeOnly` `NeedsReview` is possible.

**Authority and proof.** ADR [0018](../adr/0018-bound-legacy-verification-authority.md);
phase tests exercise positive and negative differentials and replay; transport
and claim gates prevent broader authority.

**Remaining caveat.** This does not attribute a template engine and never
executes an OS command or file read.

### Local-file review

**Original problem.** Sensitive default file probes or marker delivery could be
presented as local-file inclusion.

**Resolution: Fixed.** The capability remains quarantined.
`crates/venom-scanner/src/phases/phase8_lfi_xxe.rs` has no default file probe. A
host must explicitly provide and authorize a benign two-nonce canary; four
matched observations can produce only `KnowledgeOnly` `NeedsReview`.

**Authority and proof.** ADR [0018](../adr/0018-bound-legacy-verification-authority.md);
tests prove zero default dispatch, benign-fixture review, non-confirming single
markers, and bounded failure behavior; architecture gates restrict transport
and claims.

**Remaining caveat.** The host owns canary provisioning and authorization. No
sensitive Linux, Windows, credential, or cloud files are product defaults.

### XXE

**Original problem.** Configuration or out-of-band delivery could imply an XXE
capability without callback proof.

**Resolution: Quarantined.** The compatibility surface is inert:
`crates/venom-scanner/src/phases/phase8_lfi_xxe.rs` performs no XML or
out-of-band dispatch, including when compatibility OOB configuration exists.

**Authority and proof.** ADR [0018](../adr/0018-bound-legacy-verification-authority.md);
zero-dispatch tests and the migrated-transport architecture gate.

**Remaining caveat.** No XXE verifier exists; that capability remains deferred.
A future implementation requires a new safe, correlated authority contract.

### SSRF

**Original problem.** Payload delivery or a target response could be interpreted
as proof of server-side request forgery.

**Resolution: Quarantined.** `crates/venom-scanner/src/phases/phase9_ssrf.rs` is
inert by default. Explicit host configuration can create only a nonce-correlated
probe receipt; literal IP addresses, `.localhost`, `.local`, and `.internal`
names are rejected and findings remain empty.

**Authority and proof.** ADR [0018](../adr/0018-bound-legacy-verification-authority.md);
tests prove default zero dispatch, empty results for 200/401/403 delivery,
destination validation, cancellation, and budget behavior; claim and transport
gates prevent escalation.

**Remaining caveat.** There is no callback collector or verifier, so that
capability remains deferred and delivery cannot change a vulnerability outcome.
The syntactic domain filter performs no DNS resolution; the host must prevent a
public-looking callback name from resolving to an unauthorized address.

## Plugin and platform boundaries

### Fake production detector plugins

**Original problem.** Stock SQL/XSS/SSTI/LFI/XXE/SSRF plugins manufactured
finding and severity truth from marker-like observations.

**Resolution: Removed.** No production detector-plugin directory remains.
Harmless INFO-only code under `examples/plugin-fixtures/` exists solely to test
the trait lifecycle and makes no security claim.

**Authority and proof.** ADR
[0019](../adr/0019-host-own-plugin-execution.md); recursive plugin architecture
policy in `xtask/src/architecture/plugin.rs` rejects the removed inventory,
finding/severity/outcome authority, and direct transport across production,
fixtures, and templates.

**Remaining caveat.** A host may supply trusted native plugins, but their output
is still observation-only.

### Plugin host authority

**Original problem.** Plugins could receive loose target data, own transport,
and return finding-like records.

**Resolution: Fixed.** Plugin API `0.2.0` in
`crates/venom-scanner/src/plugin.rs` receives host-owned subject/origin,
cancellation, immutable limits, a bounded broker and accounting authority,
redaction policy, and case identity. It records bounded evidence-only
observations atomically and cannot author findings, severities, hypotheses, or
outcomes.

**Authority and proof.** ADR [0019](../adr/0019-host-own-plugin-execution.md);
plugin unit/integration tests cover provenance, redaction, duplicate identity,
in-flight unregister/re-register, budgets, rollback, cancellation, timeout, and
panic; `xtask/src/architecture/plugin.rs` pins the trait and forbidden authority.

**Remaining caveat.** Plugins are trusted, linked native code, not a dynamic or
process sandbox.

### API fake startup

**Original problem.** An API command could return startup success without
binding a supported listener.

**Resolution: Quarantined.** The false-success behavior is fixed:
`crates/venom-api/src/lib.rs`
keeps a small router contract but makes `start_api` return typed `Unsupported`
without binding. The CLI adapter is opt-in and absent from the default build.

**Authority and proof.** ADR
[0020](../adr/0020-quarantine-platform-and-distribution-surfaces.md); API unit
and CLI integration tests require nonzero fail-closed behavior; exact feature
and dependency gates live in `xtask/src/architecture/platform.rs`.

**Remaining caveat.** A supported API listener remains deferred.

### Fake MITM surface

**Original problem.** A proxy surface implied HTTP/TLS interception although it
was only a TCP relay.

**Resolution: Quarantined.** `crates/venom-proxy` is explicitly a fixed-upstream
TCP relay. The CLI uses typed `SocketAddr` parsing, accepts bracketed IPv6,
requires an explicit upstream, and rejects malformed or incomplete arguments
before dispatch. The relay has no CONNECT, TLS certificate, inspection, or
dynamic upstream authority and is absent from the default CLI.

**Authority and proof.** ADR [0020](../adr/0020-quarantine-platform-and-distribution-surfaces.md);
CLI parse/fail-closed tests in `crates/venom-cli/src/main.rs` and
`crates/venom-cli/tests/decision_scan_cli.rs`; loopback-only relay tests and
platform feature/module gates; current truth is also documented in the
[runtime map](../internals/runtime-map.md).

**Remaining caveat.** A MITM proxy remains deferred; Venom does not provide one.

## Distribution truth

### Container

**Original problem.** Image defaults implied a supported service/platform.

**Resolution: Quarantined.** The container is inert local packaging. The root
`Dockerfile`
builds the locked default CLI, runs as a non-root user, has the `venom`
entrypoint and `--help` command, and defines no exposed service or health check.

**Authority and proof.** ADR [0020](../adr/0020-quarantine-platform-and-distribution-surfaces.md);
`tests/distribution/container-contract.sh`, the Distribution Contracts CI job,
and deployment architecture gates. `.github/workflows/deploy.yml` is manual
only, requires an explicit `publish` input, and uses commit-scoped development
tags instead of publishing on ordinary branch pushes. The
[distribution documentation](../DISTRIBUTION.md) labels the image a
source/local/manual developer artifact.

**Remaining caveat.** There is no supported published registry image or service
runtime. Container execution still depends on a host-provided authorized target.

### Compose

**Original problem.** A root Compose stack advertised an unsupported platform.

**Resolution: Removed.** Root `docker-compose.yml`, `docker-compose.yaml`,
`compose.yml`, and `compose.yaml` are absent.

**Authority and proof.** ADR [0020](../adr/0020-quarantine-platform-and-distribution-surfaces.md);
`xtask/src/architecture/deployment.rs` rejects executable root/infra manifests;
the [deployment blueprint](../experimental/deployment-blueprint.md) is explicitly
future-only.

**Remaining caveat.** Supported deployment remains deferred until a real
listener, state model, threat model, and security review exist.

### Installer

**Original problem.** A repository installer suggested release, checksum, and
platform support that the project did not provide.

**Resolution: Removed.** Root and `scripts/` installers are absent.

**Authority and proof.** ADR [0020](../adr/0020-quarantine-platform-and-distribution-surfaces.md);
`xtask/src/architecture/deployment.rs` forbids installer reintroduction and
[distribution documentation](../DISTRIBUTION.md) describes supported source and
archive workflows only.

**Remaining caveat.** Installer support remains deferred. A future installer
requires real release provenance, checksum, platform, upgrade, and uninstall
contracts.

## Bounded host-library surfaces

### Reporting encoding

**Original problem.** Stringly rendering risked injection, private-data
expansion, unbounded output, and partial/truncated success.

**Resolution: Fixed.** `crates/venom-scanner/src/reporting.rs` renders the typed,
minimized `RunReport` projection as `venom-rendered-run/v1` JSON, CSV, HTML, or
Markdown through checked buffers under a 16 MiB hard ceiling. It applies
format-specific encoding and returns typed failure without a partial result.

**Authority and proof.** ADR
[0021](../adr/0021-render-bounded-run-reports.md); renderer tests cover all
formats, incomplete lifecycle labels, private-field omission, HTML/CSV/Markdown
injection defenses, control characters, exact caps, determinism, and opaque
errors; `xtask/src/architecture/platform.rs` fingerprints the surface and blocks
ambient I/O or verdict authority.

**Remaining caveat.** Encoding is not redaction. The host must supply already
redacted summaries and owns any persistence. The default CLI has no reporting
caller.

### Lua

**Original problem.** A registry scaffold was advertised more broadly than its
execution and isolation contracts justified.

**Resolution: Fixed.** The bounded host API is implemented while default
composition remains quarantined.
`crates/venom-scanner/src/lua_engine.rs` uses private approved-root source
snapshots, fresh Lua 5.4 VMs with no standard libraries, a private environment,
typed limits/results, memory and instruction controls, cooperative deadline and
cancellation checks, bounded output/history, and checked concurrency. The
feature has no scanner, plugin, or CLI caller.

**Authority and proof.** ADR
[0022](../adr/0022-bound-host-lua-and-distributed-execution.md); Lua engine,
configuration, source/symlink, cancellation, deadline, concurrency, privacy, and
return-domain tests; exact feature/API/body/ambient-authority gates in
`xtask/src/architecture/platform.rs`.

**Remaining caveat.** This is cooperative in-process control, not process
isolation. It cannot hard-preempt parser/native/allocator work, and the approved
root, caller data, and host instance budget remain trust boundaries.

### Distributed coordinator

**Original problem.** Split concurrent maps and aspirational labels implied a
coherent distributed control plane that did not exist.

**Resolution: Fixed.** The process-local contract is implemented while product
composition remains quarantined. `crates/venom-scanner/src/distributed.rs`
implements one bounded, revisioned, logical-time state machine with
deterministic ordered selection, generation-fenced leases, explicit
retry/recovery, private snapshots, checked
counters, and bounded receipt-only result retention.

**Authority and proof.** ADR [0022](../adr/0022-bound-host-lua-and-distributed-execution.md);
distributed unit/integration/race/model tests cover atomicity, capacity,
ordering, tie-breaks, lease expiry, retries, cancellation/completion races,
idempotency, and result bounds; architecture gates require a dependency-free,
default-excluded, ordered/integer-only, ambient-authority-free feature.

**Remaining caveat.** A durable distributed control plane remains deferred.
There is no network transport, authentication, serialization, persistence,
coordinator epoch, background service, exactly-once guarantee, or multi-node
control plane. Tokens are logical fences inside one caller-enforced epoch, not
authentication.

### Optional platform and analysis surfaces

**Original problem.** Reporting, dashboard, persistence, realtime,
post-exploitation, WAF compatibility, detection records, semantic extraction,
and defense records were default-compiled despite having no product caller;
`mlua` was unconditional.

**Resolution: Quarantined.** `crates/venom-scanner/Cargo.toml` and
`crates/venom-scanner/src/lib.rs` assign platform records to
`platform-models`, advanced detection/anomaly records to `detection`, reporting
to `reporting`, and Lua to `lua`. Semantic extraction and defense remain
bounded host APIs and are not automatically composed into either CLI scan.
Retired WAF and other false platform facades remain absent.

**Authority and proof.** ADRs [0020](../adr/0020-quarantine-platform-and-distribution-surfaces.md),
[0021](../adr/0021-render-bounded-run-reports.md), and
[0022](../adr/0022-bound-host-lua-and-distributed-execution.md); exact feature,
dependency, module, facade, lifecycle, and default-reachability inventories in
`xtask/src/architecture/platform.rs`; independent feature slices in
`.github/workflows/tests.yml`.

**Remaining caveat.** These modules may be useful to explicit library hosts,
but compilation or an example is not product composition and does not confer
runtime, network, persistence, or verdict authority.

### Default feature closure

**Original problem.** Default scanner compilation mixed the deterministic
runtime, legacy runner, detector/platform records, and unsupported shells.

**Resolution: Fixed.** `crates/venom-scanner/Cargo.toml` defines the default as
exactly `core + scanning`. Legacy scanner, plugins, reporting, Lua, distributed,
platform models, API, and proxy remain independent opt-in closures. Historical
`full`, `enterprise`, and `research` names are compatibility feature aggregates,
not operational scan profiles.

**Authority and proof.** Exact feature/dependency/module/re-export inventories
in `xtask/src/architecture/platform.rs`; independent feature closures and
aggregate checks in `.github/workflows/tests.yml`; current composition in the
[runtime map](../internals/runtime-map.md).

**Remaining caveat.** Compilation is not runtime composition. An opt-in host
library does not silently become a product capability.

## Validation and remaining external work

The reviewed implementation head `df19f00ea2171cd8486a6256cb318755d063fb47`
has 26 terminal PR checks: 23 successful, two intentionally skipped, one
neutral external scanner, and no failures or pending work. The accepted coverage record is
[`83069a04e6fc.json`](../reports/coverage/83069a04e6fc.json): aggregate
`21,439 / 24,842` (`86.301425%`) and patch `10,345 / 11,966`
(`86.453284%`). Coverage is a regression/navigation signal, not proof of
correctness or security.

This closure does **not** claim production readiness. Independent security
assessment, external adoption, stable Scanner SDK/plugin compatibility,
endpoint-scale performance evidence, and an upgrade/deprecation lifecycle
remain release gates in the repository-root `PROJECT_STATUS.md`.
The published `v0.9.0-alpha` GitHub Release also predates this runtime; annotating
or deprecating that external release metadata is a separate repository action.
