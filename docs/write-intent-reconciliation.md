# Write Intent Reconciliation

This milestone adds a narrow evidence layer above the audit contract. It answers
one question: for the declared inputs in a host/window/run, can GuardedOps
explain every known write operation with an exact intent, wrapper audit, hook
block, or declared external evidence record?

It does not prove that no other writes happened outside the declared evidence
sources.

## Schemas

### `guardedops.intent/v1`

`opsctl` records a write intent before a supported controlled write is
transported or applied. This version covers `apply-config-batch`, `deploy-ref`,
`restart-service`, `safe-git` fetch/checkout, and the maintenance
`install-wrapper` path.
The intent carries the exact `operation_id` that `ops-wrapper` must reuse in
`guardedops.audit/v1` records for the same operation.

Required intent fields are:

- `schema_version`: `guardedops.intent/v1`
- `operation_id`: stable correlation key, exact match required
- `run_id`
- `ts`
- `host`
- `action`
- `operation_kind`
- `status`
- `transport`
- `command`
- `details`

Write intents use `operation_kind=write` and `status=planned`. Synthetic read
intent records may be present in input files, but they are excluded from the
write denominator.

Intent persistence is part of the safety contract: if the intent append cannot
be durably written, the write side effect must not run.

### `guardedops.audit/v1`

Wrapper-managed writes are complete only when the same `operation_id` has a
valid audit sequence:

- `start/started`
- terminal `result/success` or `result/failed`

Policy denial remains a single terminal `result/failed` record with a stable
reason code. A start record without a terminal result is `incomplete`.

### `guardedops.evidence/v1`

Hook blocks and external writes are first modeled as explicit JSONL evidence
inputs to reconciliation. Required fields are:

- `schema_version`: `guardedops.evidence/v1`
- `operation_id`
- `run_id`
- `ts`
- `host`
- `source`
- `status`
- `details`

`operation_kind` defaults to `write` when omitted. `reason_code` is optional and
is used for stable classifications such as `hook_denied`,
`hook_blocked`, or `external_write_detected`.

The first version intentionally treats this as declared evidence. A JSONL file
with `source=external-ssh` says what the caller declares; by itself it does not
prove source authenticity, host file integrity, or that every external channel
was observed.

Local legacy writes, bootstrap, rollback-record maintenance, and writes made
outside those controlled actions are not silently counted as intent-ledger
coverage. They remain out of scope until supplied as explicit external evidence
or instrumented in a later milestone.

`install-wrapper` is treated as a controlled maintenance write. `opsctl` writes
intent plus local start/result audit before and after SSH transport, records
the declared wrapper/policy/runtime paths, creates a backup manifest under the
policy `backup_dir`, and records candidate/backup/before/after hashes. It does
not prove that an unrelated remote actor could not edit the same files.

## CLI

Offline reconciliation requires explicit inputs:

```bash
ops-review audit-reconcile \
  --intent synthetic/intent.jsonl \
  --audit synthetic/audit.jsonl \
  --evidence synthetic/evidence.jsonl \
  --run-id run-example \
  --output synthetic/reconcile.json
```

Daily evidence renders a reconciliation report into a JSON source of truth plus
a safe Markdown summary:

```bash
ops-review daily-evidence \
  --input synthetic/reconcile.json \
  --output synthetic/daily
```

Exit codes:

- `0`: `complete`
- `3`: `partial`
- `2`: `insufficient`

Normal blocked operations do not make the report fail. Evidence gaps do.

## Denominator and coverage

The known write universe is the `operation_id` union of:

- write intents
- wrapper write audit operations
- hook block evidence
- declared external write evidence

Coverage is:

```text
known_write_coverage_ratio = explained_writes / known_writes
```

`known_writes=0` is not green. It is `insufficient` with
`insufficient_exposure`, because there was no write exposure to validate.

Missing required input sources are also `insufficient`. The report can only judge
the sources supplied to the command.

## Verdict rules

`complete` means every known write in the declared input scope is explained and
there are no malformed, legacy, duplicate, incomplete, missing, or conflicting
records.

`partial` is returned for evidence gaps, including:

- intent without wrapper audit or hook explanation
- wrapper write audit without intent
- duplicate operation IDs
- metadata conflict between intent and audit
- incomplete wrapper audit
- invalid audit sequence
- malformed JSONL
- legacy audit records
- unknown schemas
- declared external writes

`insufficient` is returned for:

- missing or unreadable required inputs
- invalid filters
- zero known writes in the selected scope

## Redaction boundary

JSON reconciliation output is the source of truth. Markdown daily evidence is a
safe render of selected counters and verdict fields.

GuardedOps does not store token values, config values, raw stdout, raw stderr,
or full diffs in intent or reconciliation details. Command and details fields
are sanitized before output.

## Observation protocol

For real observation, run a fixed 2-4 week process instead of relying on a single
successful test run:

1. Define the daily host/window/run scope and the expected input sources:
   intent ledger, wrapper audit log, hook evidence, and any declared external
   evidence feed.
2. Record source inventory for every report: path, producer, collection time,
   and a content hash of each input artifact.
3. Run `ops-review audit-reconcile` for each host/window/run and save the JSON
   report as the judgment artifact.
4. Run `ops-review daily-evidence` to produce a human-readable Markdown summary.
5. Track at minimum: `known_writes`, `explained_writes`, missing intent, missing
   wrapper audit, incomplete audit, hook blocks, external writes, malformed
   records, and source health.
6. Review weekly exposure volume. A week with no real writes cannot support a
   reliability claim.

Only if there is real write exposure, every declared source is healthy, and
evidence gaps remain zero for the observation window can the system be described
as complete within that declared test or observation scope.

## Out of scope

This milestone does not implement or prove:

- current-turn authorization
- real rollback safety
- root or direct SSH bypass prevention
- CI/CD evidence integration
- host file integrity
- business correctness
- incident causality

The defensible claim is narrower: under test and declared observation inputs,
wrapper-managed writes can be reconciled against recorded intent and audit
evidence.
