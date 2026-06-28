# Session Review

`ops-review` never reads a default real session directory. Input is required.

```bash
ops-review collect --input examples/session-review/sessions --output .guarded_ops/review
ops-review report --output .guarded_ops/review
```

The output keeps command hashes and normalized templates instead of raw command
transcripts.

