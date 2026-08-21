# Coverage evidence

Venom's Tests workflow measures repository-owned Rust source with Rust `1.88.0`
and `cargo-tarpaulin 0.37.2`. Tarpaulin itself is compiled with pinned installer
Rust `1.91.0`, while the measurement command explicitly selects `1.88.0`. The
job retains `cobertura.xml` plus deterministic JSON and Markdown summaries in
the `coverage-evidence` workflow artifact. It attempts a best-effort advisory
Codecov upload, but tokenless availability is not required or enforced; the
repository-owned checker is the policy authority.

## Current state: calibration

There is no accepted coverage baseline in this source state. The workflow
therefore runs `scripts/coverage_gate.py --calibrate`. Calibration validates
the report and base-to-head patch inputs, fails if a changed in-scope source
file is absent, and emits evidence, but it does not enforce an invented
percentage. Calibration also fails if an accepted baseline pointer already
exists, so it cannot remain enabled after acceptance by accident.

An accepted baseline requires all three committed files:

- `docs/reports/coverage/<7-40 lowercase commit prefix>.json`;
- the byte-for-byte canonical Markdown rendering at the matching `.md` path;
- `docs/reports/coverage/accepted-baseline.txt`, containing the JSON path on one
  line.

The generated [report template](TEMPLATE.md) describes the human-readable
shape. The JSON summary is the machine-readable source of truth.

## Fixed measurement contract

The measured source scope is:

- tracked Rust files under `crates/*/src/**`;
- tracked Rust files under `xtask/src/**`.

Tarpaulin is installed exactly with:

```bash
rustup toolchain install 1.91.0 --profile minimal
cargo +1.91.0 install cargo-tarpaulin --version 0.37.2 --locked
```

Coverage then runs exactly with the measurement toolchain:

```bash
cargo +1.88.0 tarpaulin --locked --workspace --all-features --ignore-tests --ignore-config --out Xml --timeout 300
```

`--ignore-config` is part of the reviewed command so neither repository
auto-configuration nor `CARGO_TARPAULIN_CONFIG_FILE` can change the measured
scope behind the recorded command.

To prevent production code from disappearing only while coverage is measured,
the checker rejects the Rust `tarpaulin`/`tarpaulin_*` cfg-token family
(including `tarpaulin_include`), `coverage(off)`, and the legacy `no_coverage`
attribute in every tracked in-scope source blob. The scan understands comments,
character/string literals, nested block comments, and raw strings, so
documentation and the reviewed workflow command may name the tool. The existing
Tarpaulin cfg on an out-of-scope integration test remains outside this
production-source policy.

The workflow-level environment is exact: only `CARGO_TERM_COLOR=always` and
`RUST_BACKTRACE=1` are inherited. Its push and pull-request triggers are pinned
to `main` and `develop` without path exclusions, and the coverage job must live
under the one canonical top-level `jobs` mapping. Job-level defaults pin Bash
and the repository root, so workflow-level run defaults cannot redirect or
replace the measured commands. The architecture gate and checker both require
the tracked `.cargo/config.toml` to contain only the reviewed `xtask` alias and
forbid legacy `.cargo/config`; the architecture gate additionally rejects
workspace custom-build targets. These rules keep repository-controlled compiler
flags, wrappers, targets, and build scripts from changing the instrumented
program behind the recorded command.

The JSON records the full source commit; exact measurement Rust, installer Rust,
Tarpaulin, runner target, command, and timeout; `Cargo.lock` and Cobertura
SHA-256 digests; include and exclude scope; aggregate and per-file integer
counts; omitted in-scope files; and GitHub run/artifact provenance. Paths must
be canonical, repository relative, portable ASCII, and contained by the
workspace. Accepted evidence is bound to the canonical `ITherso/venom`
repository and positive Actions run and attempt identifiers; unknown JSON
fields are rejected.

## Accepting the first baseline

1. Use a successful calibration artifact from the exact commit under review.
2. Verify its commit, workflow run, artifact, digests, scope, tool versions, and
   per-file/omission inventory.
3. Commit its JSON and canonical Markdown using the source-commit prefix, then
   add `accepted-baseline.txt` pointing to that JSON.
4. Rename the workflow step to enforcement and remove `--calibrate` from the
   checker invocation. The architecture gate automatically requires that exact
   enforcement form when the accepted pointer exists, without changing measured
   `xtask/src/**` code in the acceptance commit.
5. Let CI validate the candidate against its own measurement before accepting
   the change.

Acceptance must be a dedicated transition from the record's `source.commit`.
Only `docs/**`, `README.md`, `FEATURES.md`, `mkdocs.yml`, and the Tests workflow
may change; every other tracked path is frozen. For the first baseline the
workflow change must be exactly the calibration-to-enforcement step-name and
argument flip. A replacement baseline must leave that workflow byte-identical.
This prevents unchanged line counts from blessing source logic or build-input
changes made after the recorded calibration run.

The commit accepting evidence must preserve the recorded `source.commit` in its
ancestry, using a merge commit or fast-forward. Squashing or rebasing the
measured commit changes its identity and fails closed; regenerate evidence for
the rewritten commit instead. The workflow keeps full Git history with
`fetch-depth: 0`. A base record's source commit does not need to be an ancestor
of a divergent PR head: enforcement reads the fetched commit's blobs directly.

Calibration writes a patch row for every changed in-scope file. If Cobertura
omits one, calibration may pass only when the same path is explicit in the
current `omitted_in_scope_files` inventory. Its row retains the actual changed
line count with zero observed covered and coverable counts. Those zeroes describe
instrumentation output, not proof that the source has no executable lines; the
row makes the omission reviewable without inventing coverage. The initial
calibration requires the entire omission inventory to equal exactly:

- `crates/venom-core/src/lib.rs`;
- `crates/venom-core/src/models.rs`;
- `crates/venom-scanner/src/adaptive/mod.rs`;
- `crates/venom-scanner/src/contracts.rs`;
- `crates/venom-scanner/src/defense/mod.rs`;
- `crates/venom-scanner/src/lib.rs`;
- `crates/venom-scanner/src/phases/mod.rs`;
- `crates/venom-scanner/src/semantic.rs`;
- `crates/venom-scanner/src/web_runtime/api_visibility/tests.rs`.

Normal mode fails closed on a missing or malformed record, a zero aggregate
or per-file denominator, an escaping path, a newly omitted source, or a
candidate baseline whose exact integer ratio is lower than the base commit's
accepted ratio. A first or replacement candidate's aggregate counts, every
per-file count, and omission inventory must exactly equal the current
measurement; a lower fabricated floor is not accepted merely because the head
measurement exceeds it. The base commit's accepted omission inventory is the
normal enforcement floor; the first acceptance uses its exact candidate
inventory. An accepted omission keeps its explicit zero-observed-denominator
patch row and is excluded from the patch ratio only while its HEAD blob is
byte-identical to that path at the applicable floor record's `source.commit`.
If its content changes, it must become measured; a replacement candidate cannot
re-bless the changed omitted blob. An addition to the omission inventory remains
a hard failure. So does disappearance from Cobertura of a source measured in the
applicable accepted baseline and still present at HEAD.
A Cobertura class with no line records is treated as omitted under the same
rules. Head aggregate coverage must not fall below the accepted ratio. Pull
requests use their base SHA and branch pushes use the event's `before` SHA;
coverable changed lines must meet the same ratio in either case. A missing,
all-zero, or unresolvable base fails closed, including a first-creation push to
a configured branch. A patch with zero observed coverable changed lines is
reported as N/A. Ratio comparisons use integer cross multiplication, not rounded
percentages.
