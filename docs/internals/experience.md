# Experience classification

`ExperienceStore` is an append-only, subject-scoped audit of completed attempts. It helps the planner avoid repeating verified negatives without interpreting temporary execution failures as evidence that an action has no utility.

Verifier outcomes and experience dispositions are separate contracts:

- `OutcomeStatus` states what a verifier concluded.
- `ExperienceDisposition` states how that result may influence later planning.

Transport, executor, target, and host-policy failures therefore do not expand the core verifier status model.

## Disposition policy

| Disposition | Meaning | Suppression streak |
| --- | --- | --- |
| `ConfirmedPositive` | The hypothesis was verified | Reset |
| `VerificationRejected` | A verifier rejected the hypothesis | Increment |
| `ConfirmedNegative` | An audited negative control disproved the hypothesis | Increment |
| `NotApplicable` | The action does not apply to this subject | Neutral |
| `BlockedByTarget` | The target denied or rate-limited the attempt | Neutral |
| `BlockedByPolicy` | Host authorization or safety policy refused execution | Neutral |
| `TransportFailure` | Network transport failed before a conclusion | Neutral |
| `ExecutorFailure` | The selected executor failed | Neutral |
| `VerificationInconclusive` | Evidence did not support a deterministic conclusion | Neutral |

Neutral observations neither increase nor erase the streak. Only `ConfirmedPositive` resets it. The planner suppresses an action after the configured number of `VerificationRejected` or `ConfirmedNegative` observations for the same subject and action.

This policy is deliberately unweighted. A timeout never receives the same penalty as a trusted negative control, and the store does not infer reliability from error strings.

## Recording

`ExperienceStore::observe` applies a conservative mapping:

| Outcome status | Inferred disposition |
| --- | --- |
| `Success` | `ConfirmedPositive` |
| `Blocked` | `BlockedByTarget` |
| `Unknown` / `NeedsReview` | `VerificationInconclusive` |
| `FalsePositive` | `VerificationRejected` |
| `ConfirmedNegative` | `ConfirmedNegative` |

Hosts with structured provenance may use `observe_with_disposition` to distinguish operational causes. `NotApplicable`, `BlockedByPolicy`, `TransportFailure`, and `ExecutorFailure` attach only to an `Unknown` or `NeedsReview` outcome, so they cannot accidentally trigger false-positive rejection or target-block adaptation semantics. The store validates every disposition/status pair. Planner exclusions are not fed back into Experience; doing so would create circular suppression.

Executor and transport failures do not currently create synthetic verifier outcomes. Typed runtime attempt receipts will carry those dispositions when operational recording is integrated.

## Persistence compatibility

New records serialize their disposition explicitly. JSON and other self-describing archives created before the field existed remain readable by the new model: deserialization infers the conservative mapping above, then validates sequence, identity, and status compatibility. This is an old-to-new migration guarantee, not a promise that ordinal-based binary formats or older binaries can understand every new enum variant. Replaying the same outcome with a different disposition is an identity conflict rather than a silent reclassification.
