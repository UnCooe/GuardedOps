# Audit Contract

GuardedOps audit records use append-only JSON Lines. The current schema is
`guardedops.audit/v1`; summaries use `guardedops.audit-summary/v1`.

## Event Schema

Every v1 event has exactly these fields; missing fields, extra fields, invalid
enums, and invalid field types are not accepted as v1 records. Identifiers use
a bounded safe character set, timestamps are valid RFC3339 values with an
explicit timezone, and actions must be registered wrapper actions:

- `schema_version`: `guardedops.audit/v1`
- `operation_id`: stable identifier shared by a write start and result
- `run_id`: operator-supplied run id or a generated id
- `ts`: UTC timestamp
- `host`: policy host name
- `action`: wrapper command action
- `operation_kind`: `read` or `write`
- `phase`: `start` or `result`
- `status`: `started`, `success`, or `failed`
- `reason_code`: terminal failure code, or `null`
- `details`: redacted allowlisted metadata only
- `wrapper_version`: wrapper release version
- `policy_version`: loaded policy version

Read operations emit one `result` record. Write operations validate policy,
approval, paths, refs, and config allowlists first, then append a durable
`start` record before the first backup, config, git, or service side effect.
They append a terminal `result` record after execution.

Policy precondition denials are represented as a single write `result` record
with `status=failed` and `reason_code=policy_denied`. Execution failures after
a start are closed with `status=failed` and a stable reason such as
`command_failed`.

Audit `details` are allowlisted per action and redacted. A v1 record containing
detail keys that are not registered for its action is invalid. Approval
material, config values, raw stdout, raw stderr, and raw command output are not
written to audit records.

## Fail-Closed Writes

Audit append validates the complete event before writing. It writes one encoded
line with append mode, verifies that `os.write` accepted the complete encoded
line, flushes it with `fsync`, and only then lets the wrapper continue.

If a write `start` cannot be appended, the wrapper exits `2` and blocks the
state-changing operation. If a terminal `result` cannot be appended after a
write has started execution, the wrapper exits `2` with a `no-auto-retry` and
`manual-verification` message. That failure leaves the earlier start incomplete
so reviewers can see that manual reconciliation is required.

This is a local durable append contract for the configured audit file. It is
not a cross-host transaction guarantee and it does not prove that downstream log
shipping has succeeded.

## Summary Semantics

The shared summary parser powers:

```bash
ops-review audit-summary --input <audit.jsonl>
ops-wrapper --policy <policy.json> audit-summary
opsctl audit-status --host <fleet-host>
```

All three support run filtering with `--run-id`; the parser also supports
`--host` and structurally validated `--since` timestamps where the command
surface can pass them through. The `ops-review` command may write the rendered
summary with `--output` and still prints the same JSON to stdout.

Filters are applied before scoped source-format and quality counts. Unrelated
legacy records and v1 records from other hosts, runs, or windows do not taint a
matching summary. A host filter is also used as the host context for a selected
legacy record that has no host field. `--since` compares parsed instants rather
than timestamp strings. Malformed JSON lines are unattributable, so they still
make a filtered summary partial. If a filter selects no records, the verdict is
`partial`, exit `3`, with reason `no_matching_records`.
An invalid `--run-id` or `--since` filter is an input error and returns
`insufficient`, exit `2`.

Each summary includes:

- `counts_by_reason_code`: terminal reason code counts
- `counts_by_action`: one count per normalized v1 operation and per legacy record
- `counts_by_status`: terminal v1 statuses plus incomplete, invalid, and legacy statuses
- `window`: first and last selected parseable timestamps, normalized to UTC
- `hosts`: selected host index, including explicit host context for hostless legacy records
- `run_ids`: selected v1 run id index

Summary verdicts measure evidence completeness, not business success:

- `complete`, exit `0`: v1 evidence is structurally complete. Failed and
  rejected terminal operations can still be complete.
- `partial`, exit `3`: evidence exists but includes legacy records, malformed
  lines, unknown schemas, empty input, incomplete starts, orphan terminal
  results, duplicate events, inconsistent metadata, or out-of-order event
  sequences. Strict-v1 validation failures are reported as unknown records with
  reason `invalid_v1_record`.
- `insufficient`, exit `2`: the audit source is missing or unreadable, or the
  wrapper/transport could not return a summary.

The `version` and `audit-summary` commands do not emit audit records.

## Compatibility

The summary parser recognizes legacy GuardedOps and aiserver-prod-ops-shaped
records only for compatibility reporting. Their action, status, parseable
timestamp, and available or filter-supplied host context are indexed. Legacy
records make the verdict `partial`; they are not upgraded into v1 operations.
