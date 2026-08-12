# Session Review

`ops-review` never reads a default real session directory. Input is required.

```bash
ops-review collect --input examples/session-review/sessions --output .guarded_ops/review
ops-review report --output .guarded_ops/review
```

The output keeps command hashes and normalized templates instead of raw command
transcripts.

Audit logs can be summarized without reading session transcripts:

```bash
ops-review audit-summary --input .guarded_ops/demo-local/audit.jsonl
ops-review audit-summary --input .guarded_ops/demo-local/audit.jsonl \
  --run-id run-20260811 --output .guarded_ops/review/audit-summary.json
```

The audit summary verdict is about evidence completeness. A denied or failed
operation can still produce a complete audit trail.

Write intent reconciliation compares explicitly supplied intent, audit, and
optional evidence JSONL files. It does not read a default production path.

```bash
ops-review audit-reconcile \
  --intent synthetic/intent.jsonl \
  --audit synthetic/audit.jsonl \
  --evidence synthetic/evidence.jsonl \
  --run-id run-example \
  --output .guarded_ops/review/reconcile.json

ops-review daily-evidence \
  --input .guarded_ops/review/reconcile.json \
  --output .guarded_ops/review/daily
```

The reconciliation denominator is the union of known write `operation_id`s from
write intents, wrapper write audit operations, hook block evidence, and declared
external write evidence. `known_write_coverage_ratio` is
`explained_writes / known_writes`.

`known_writes=0` is `insufficient`, not green. Missing sources are
`insufficient`. Evidence gaps such as missing intent, missing wrapper audit,
duplicate operation IDs, metadata conflicts, incomplete audit sequences,
malformed input, unknown schemas, or legacy audit records are `partial`.

The JSON report is the judgment source. The Markdown daily evidence output is a
safe render for humans and omits raw details.
