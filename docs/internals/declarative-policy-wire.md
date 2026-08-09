# Declarative policy wire contracts

Surface B exposes serializable rule and policy types for library hosts, even
though the built-in web profile constructs them in Rust. These objects are
security semantics, not free-form metadata: losing a matcher, scope, or
condition must not silently make a rule apply more broadly.

The built-in CLI does not load reasoning, verification, or adaptation rules
from remote responses or local configuration. The contracts on this page are
therefore host-facing and preparatory for future declarative profiles; they are
not a claim that the default CLI accepts an attacker-supplied policy file.

## Strict semantic objects

Unknown fields reject in the following complete policy objects and their
private wire representations:

- expression nodes;
- evidence selectors, calibrations, conclusions, and reasoning rules;
- outcome selectors, pipeline directives, and adaptation rules;
- verification rules.

These types have no documented extension namespace. Accepting an unknown field
would let a spelling error erase a constraint. Objects that intentionally carry
extensions, such as `AttackAction` and `VerificationCase`, retain that behavior
but reject unknown names in their reserved policy namespaces.

## Missing is different from explicit null

Three nullable fields must be present on the wire:

| Object | Field | Explicit `null` | Missing field |
| --- | --- | --- | --- |
| claim expression | `value` | predicate existence | reject |
| evidence selector | `value` | predicate existence when no other matcher is present | reject |
| adaptation rule | `condition` | deliberately unconditional rule | reject |

This preserves the historical serialized shape. Existing serializers already
emitted these fields, including `null`; the reader now distinguishes that
explicit choice from an omitted or misspelled field.

## Compatibility guards

Canonical non-default policies emit a small guard describing the constraint
that must still be present:

| Policy | Canonical guard | Protected loss |
| --- | --- | --- |
| constrained evidence selector | `matcher_policy_guard: true` | exact/text/list matcher |
| bounded evidence calibration | `aggregation_policy_guard: true` | contribution cap |
| scoped verification rule | `verification_scope_guard` | action, case, or both |
| conditional adaptation rule | `condition_policy_guard: true` | condition |

A present guard must exactly agree with the semantic fields. Guardless policy
objects produced by the immediately preceding format remain readable and are
canonicalized with a guard when serialized again. Default existence,
independent aggregation, unscoped verification, and explicitly unconditional
adaptation remain guardless.

These guards detect a missing or inconsistent semantic field; they are not a
cryptographic integrity mechanism. Removing both a field and its guard cannot
be distinguished from a historical default object. Archive integrity and
authentication remain the host's responsibility.

The aggregation guard is also old-reader fail-closed because the preceding
calibration reader already rejected unknown fields. The selector, verification,
and adaptation guards protect current-reader reconstruction; preceding readers
understand every existing guarded matcher, scope, and condition and therefore
preserve an intact object. A future semantic variant that an older reader does
not understand needs its own old-reader rejection design. The current guards
must not be treated as generic versioning.

## Validation boundaries

`PipelineDirective` validates standalone deserialization as well as nested rule
construction. Blank scheduled action IDs, zero throttle delays, unknown fields,
and unknown directives reject. `VerificationCase` reserves `payload_*`,
`applies_hypothesis_*`, and `verification_*`, preventing a policy-looking
extension from being ignored and reconstructed as transition-authorized.

Accepted objects still pass the same constructors and invariants used by the
programmatic API. Deserialization does not infer negative knowledge, reject a
hypothesis, or turn a missing field into `false`.

## Resource ownership

Expression evaluation, cloning, and serialization are recursive. The standard
profiles contain small fixed trees, and `serde_json` applies its own input
recursion limit, but public hosts can construct larger trees directly or use a
different deserializer. A host that introduces a declarative loader must bound
the policy byte size, tree depth, node count, string/list sizes, action count,
and dependency depth before installing it. This contract intentionally does not
invent one global limit without a production loader and measured workload.

Fuzz targets use stricter harness-only limits so scheduled campaigns remain
reproducible and cannot become an unbounded CI workload.

## Output compatibility

The built-in web profile, request behavior, planner utility, verification
outcomes, hypothesis states, `ExperienceStore`, `AttackPlan`, and
`decision-scan/v1` output are unchanged. The only wire-shape additions are
guards on non-default declarative policy definitions. Public-library hosts that
previously relied on unknown fields inside strict semantic objects now receive
an error instead of a broader policy.
