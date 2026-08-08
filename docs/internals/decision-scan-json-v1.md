# `decision-scan` JSON output — schema `decision-scan/v1`

`venom decision-scan <target> --format json` prints a single JSON document to
**stdout**; the `[PREVIEW]` warning and any error go to **stderr**. The document is
built from the same typed summary the text renderer uses — it is never produced by
parsing rendered text. `--format json` cannot be combined with `--explain` (the
JSON already carries the full diagnostics); the combination is rejected as an
argument conflict.

The `schema_version` field is the contract handle. This page pins the exact shape
of `decision-scan/v1`.

## Top-level document

| Field | Type | Notes |
| --- | --- | --- |
| `schema_version` | string | Always `"decision-scan/v1"` for this version. |
| `engine` | string | Always `"decision-preview"`. |
| `target_origin` | string | ASCII origin serialization of the authorized target. |
| `summary` | object | Aggregate counts (below). |
| `executor_routes` | object | Runtime executor-route authority (below). |
| `hypotheses` | array | Reasoning hypotheses, sorted (below). |
| `planning_turns` | array | One entry per planning turn, in order. |
| `dispatches` | array | Wire dispatches, in dispatch order. |
| `verification_outcomes` | array | Verification outcome turns, in order. |
| `terminal` | object | The bounded terminal state. |
| `usage` | object | Resource usage. |

No field is ever omitted; empty arrays are `[]` and absent scalars are `null`.

### `summary`

| Field | Type |
| --- | --- |
| `bootstrap_evidence_writes` | integer ≥ 0 |
| `planning_turns` | integer ≥ 0 |
| `verification_outcomes` | integer ≥ 0 |
| `conclusive_outcomes` | integer ≥ 0 |
| `inconclusive_outcomes` | integer ≥ 0 |
| `experience_records` | integer ≥ 0 |

Invariants: `summary.planning_turns == planning_turns.length`;
`summary.verification_outcomes == verification_outcomes.length`;
`conclusive_outcomes + inconclusive_outcomes == verification_outcomes.length`.

### `executor_routes`

| Field | Type | Notes |
| --- | --- | --- |
| `unavailable` | array of string (action ids) | Semantic actions the planner knows but the current runtime composition has **no executor route** for. Sourced from the runtime's own authority, **never** inferred from planning exclusion reasons. |

There is **no** `available` list: it is not synthesized by subtracting sets. The
inventory is a fixed property of the runtime's executor registry and is identical
regardless of the fixture/evidence.

### `hypotheses[]`

Sorted by `(predicate, value)`.

| Field | Type | Notes |
| --- | --- | --- |
| `predicate` | string | Dotted knowledge predicate, e.g. `authentication.mechanism`. |
| `value` | string \| null | Scalar string form of the value; `null` unless `value_disposition == "exposed"`. |
| `value_kind` | string enum | `text` \| `boolean` \| `signed` \| `unsigned` \| `text_list` \| `other`. |
| `value_disposition` | string enum | `exposed` \| `redacted` \| `non_scalar` \| `other`. The machine-output safety decision (below). |
| `strength` | string enum | `weak` \| `strong` \| `other`. |
| `posterior_basis_points` | integer 0..=10000 | Posterior probability in basis points. Basis points and the text-only percent are each rounded directly from the upstream probability (never one from the other). |
| `state` | string enum | `proposed` \| `supported` \| `contradicted` \| `confirmed` \| `rejected` \| `other`. |

`value_disposition` is a fail-closed safety policy on the hypothesis value: a
scalar value is `exposed` only under an allowlisted safe predicate (the standard
web technology/authentication predicates); a scalar under any other predicate is
`redacted` with `value == null` (so a future rule cannot leak a token, cookie, or
other sensitive text); a list value is `non_scalar`; an unknown value kind is
`other`. `value` is non-null only when `exposed`.

### `planning_turns[]`

| Field | Type | Notes |
| --- | --- | --- |
| `turn` | integer ≥ 0 | Zero-based turn index, in order. |
| `planned` | array of string (action ids) | Dependency-safe plan steps, in plan order. |
| `excluded` | array of object | `{ "action_id": string, "reason": string enum }`. |

`excluded[].reason` enum: `policy_suppressed` \| `defense_suppressed` \|
`requirements_not_met` \| `no_eligible_hypothesis` \| `risk_limit_exceeded` \|
`below_minimum_utility` \| `dependency_unavailable` \| `budget_exceeded` \|
`other`. Route availability (`executor_routes`) and per-turn eligibility
(`planning_turns`) are independent axes.

### `dispatches[]`

In dispatch order.

| Field | Type | Notes |
| --- | --- | --- |
| `sequence` | integer ≥ 0 | Strictly increasing dispatch order. |
| `action_id` | string | Semantic action charged for the dispatch. |
| `stage` | string enum | `passive` \| `active` \| `other`. |
| `origin` | string enum \| null | `bootstrap` \| `planned` \| `adaptive` \| `retry` \| `other`, or `null`. |

`stage` and `origin` are **separate facts**. An active-verification probe is
`stage == "active"` with `origin == null`; a consumer infers "active verification"
from that pair. (The text renderer's `active_verification` label is a
presentation-only derivation and never appears in JSON.)

### `verification_outcomes[]`

| Field | Type | Notes |
| --- | --- | --- |
| `action_id` | string | Action associated with the verification outcome. |
| `status` | string enum | `success` \| `blocked` \| `unknown` \| `false_positive` \| `needs_review` \| `confirmed_negative` \| `other`. |
| `conclusive` | boolean | Whether the case authorizes a hypothesis transition **and** the outcome maps to a verifier-owned hypothesis state. A `Success` may therefore be `false`, and no outcome is automatically a vulnerability. |

### `terminal`

| Field | Type | Notes |
| --- | --- | --- |
| `command` | string enum | `execute_action` \| `collect_active_evidence` \| `replan` \| `complete` \| `await_human_review` \| `halt` \| `other`. |
| `stop_reason` | string enum \| null | `objective_complete` \| `no_eligible_action` \| `human_review` \| `adaptation_limit` \| `action_cycle_limit` \| `runtime_budget_limit` \| `cancelled_by_host` \| `other`, or `null` when the command is not a halt. |
| `runtime_limit` | object \| null | Structured budget stop, or `null`. |

`runtime_limit` object: `{ "dimension": string enum, "limit": integer,
"observed": integer, "action_id": string | null }`. `dimension` ∈
`total_requests` \| `wall_time` \| `response_bytes` \| `request_body_bytes` \|
`active_verifications` \| `same_action_attempts` \|
`consecutive_no_progress_turns` \| `other`. Units of `limit`/`observed` depend on
`dimension`: **bytes** for `response_bytes`/`request_body_bytes`, a **count** for
the request/verification/attempt dimensions, **milliseconds** for `wall_time`.

### `usage`

| Field | Type | Units |
| --- | --- | --- |
| `total_requests` | integer | count |
| `active_verifications` | integer | count |
| `response_bytes` | integer | bytes |
| `elapsed_ms` | integer | milliseconds |

## Determinism

The semantic records and their ordering are deterministic for the **same target,
the same runtime version/configuration, and equivalent non-boundary responses** —
i.e. runs that do not sit against a transport-byte or wall-time budget boundary.

- `usage.elapsed_ms` is inherently variable across runs.
- **Near a budget boundary** (the cumulative response-byte threshold or the
  wall-time limit), TCP chunking and scheduling can affect `usage.response_bytes`,
  `terminal.runtime_limit.observed`, *which* request the bound is reached at (and
  therefore `usage.total_requests`), and potentially the terminal timing/state
  (whether the budget is crossed on this run at all). Consumers must not assume
  byte-exact equality near a boundary.

Away from boundaries, everything except `elapsed_ms` is deterministic.

## Ordering

- **Array element order is contractual**: `planning_turns` and `dispatches` are in
  execution order, `verification_outcomes` in turn order, `hypotheses` sorted by
  `(predicate, value)`, and `executor_routes.unavailable` sorted.
- **JSON object member order is not a consumer-semantic contract.** Consumers must
  address fields by name, not by position. The exact byte serialization (member
  order, whitespace) reflects the current canonical renderer and may change without
  a `schema_version` bump; only the field set, types, nullability, and the array
  orderings above are contractual.

## Data the schema does not expose

The `decision-scan/v1` schema does **not** expose raw evidence records, response
bodies, response headers, credentials, cookies, tokens, or evidence identifiers.
Every enum value is a stable snake_case label; no value is ever emitted through
Rust `Debug` formatting.

## Enum stability

All string enums are closed vocabularies with a `other` catch-all so an
unrecognized upstream variant degrades to a stable, non-`Debug` token rather than
leaking type internals or breaking parsing.

## Consumer safety guidance

`decision-scan/v1` is an **operational-diagnostics** contract. It reports what the
runtime observed, planned, dispatched, and verified — **not** security findings or
vulnerabilities. When building automation on it:

- **Read `hypotheses[].value` only when `value_disposition == "exposed"`.** For any
  other disposition the value is withheld (`null`); do not treat a missing value as
  an error, and do not read `value` unconditionally.
- **A planned action is not necessarily dispatched.** To learn whether an action
  actually ran, compare `planning_turns[].planned` against `dispatches[].action_id`
  — an action can be planned but deferred (e.g. behind human review) and never
  dispatched.
- **`status == "success"`, `state == "confirmed"`, and `conclusive == true` are
  separate verification semantics, not finding or vulnerability semantics.** A
  `Success` means the action objective was satisfied, but a knowledge-only case
  intentionally reports `conclusive == false` and leaves its motivating
  hypothesis unmodified. A transition-authorized conclusive verification means
  the runtime reached a definite answer about a detection (e.g. "this endpoint
  advertises HTTP Basic authentication", or "this page contains a Livewire
  marker") — it does **not** mean a reportable security issue.
  Detecting a technology or an authentication mechanism is not itself a
  vulnerability.
- **`confirmed_negative` is `conclusive == true` only when its case authorizes a
  hypothesis transition.** A transition-authorized definitive negative is
  conclusive too, so `conclusive` alone cannot gate any finding.
- **`redacted`, `non_scalar`, and `other` value dispositions, and the
  `confirmed_negative`, `blocked`, `needs_review`, and `false_positive` outcome
  statuses, may appear** even though the current standard fixture corpus does not
  emit all of them. Handle every documented enum value.

Turning these diagnostics into findings is the job of a separate, explicit
projection layer — not of a consumer inferring findings from these fields.

## Versioning policy

`schema_version` changes only on a **breaking** change. Within `v1`, changes are
**additive** only.

**Breaking (requires `decision-scan/v2`):**

- removing or renaming a field;
- changing a field's type;
- changing the meaning of an existing enum value;
- changing a field's nullability;
- changing an ordering or invariant guaranteed above.

**Non-breaking (allowed within `v1`):**

- adding a new, documented, optional field;
- adding a new enum value **only** where a `other` catch-all already absorbs
  unknown values (consumers must treat unknown enum values as `other`).

Consumers should ignore unknown fields and treat unknown enum values as `other`.
