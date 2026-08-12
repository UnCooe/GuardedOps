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
