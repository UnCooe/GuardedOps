# GuardedOps Audit Contract Validation Report

Validated at: 2026-08-11T13:52:00Z

## Scope

- Milestone: `guardedops.audit/v1`, shared `audit-summary`, and isolated SSH sandbox validation.
- Run id: `audit-contract-20260811T132612Z`.
- Excluded: current-turn authorization, real rollback, root/direct-SSH bypass detection, external deploy systems, and claims about all production incidents.
- Test-host routing used the managed live route. No global VPN or SSH configuration was changed.

## Local Gates

- `python3 -m unittest tests.test_audit_contract`: pass, 25 tests.
- `python3 -m unittest discover -s tests`: pass, 62 tests.
- `scripts/release_gate.sh`: pass after the final code changes, including four public leak scans and wheel/sdist builds.
- `git diff --check`: pass.

The audit tests cover successful writes, policy denials, approval and change-id
failures, an unwritable audit destination with unchanged state hashes, action
exceptions, an incomplete simulated interruption, terminal append failure,
secret redaction, malformed JSONL, strict v1 validation, event ordering, and
both legacy formats.

## SSH Matrix

All state was confined to these run-specific directories and removed after
evidence capture:

- `/opt/guardedops-demo/validation/audit-contract-20260811T132612Z`
- `/var/log/guardedops-demo/validation/audit-contract-20260811T132612Z`
- `/var/backups/guardedops-demo/validation/audit-contract-20260811T132612Z`

| Case | Expected | Observed | Audit result |
| --- | --- | --- | --- |
| `host-observe` | read succeeds | exit 0 | success |
| `runtime-baseline` | read succeeds | exit 0 | success |
| `log-query` in allowed root | read succeeds | exit 0 | success |
| `safe-git checkout` exact SHA | isolated HEAD changes | exit 0 | started, success |
| `apply-config-batch` allowed key | isolated config changes and backup exists | exit 0 | started, success |
| `restart-service` with mock adapter | isolated status/log changes only | exit 0 | started, success |
| unknown config key | blocked | exit 2 | policy_denied |
| wrong approval scope | blocked | exit 2 | policy_denied |
| mismatched change id | blocked | exit 2 | policy_denied |
| wrong service | blocked | exit 2 | policy_denied |
| non-exact Git ref | blocked | exit 2 | policy_denied |
| log path outside allowed root | blocked without reading target | exit 2 | policy_denied |

The four state hashes taken immediately before and after the six denial cases
were identical:

- config: `e73ad97f7d358b7ef1cf5a81a80ac47155c23793e941a4fe96af494d50ac052c`
- mock service status: `d08463a3fdf8eebf122fa5293c729805af5525e20bfe28a2cb11ed58366ab411`
- mock log: `cbd1449bd8901b7776137c7c865a9fca970b46b86ff17d0b9d3f5fe79e80d848`
- detached Git HEAD file: `8d8820e16f3a17ba0a4992b69a4e0ebe04a987f9ad11dbcd9521ae4bf0198c87`

## Audit Evidence

The run-filtered server summary and the local offline summary agreed:

- verdict: `complete`, exit 0
- v1 records: 15
- normalized operations: 12
- success: 6
- failed and rejected: 6
- reason `policy_denied`: 6
- incomplete, orphan, invalid sequence, malformed, unknown: 0
- audit SHA-256: `82b573c357c552b607f7fe6f4f6e663a4ae8e0373b48a45d410e2165fe32328c`

The pulled audit contained only registered per-action detail keys. A scan for
approval material, tokens, credentials, authorization/cookie data, raw
stdout/stderr, diffs, and config values returned no matches.

The existing 14 legacy GuardedOps records were analyzed separately:

- verdict: `partial`, exit 3
- source format: `legacy_guardedops`
- normalized v1 operations: 0
- action/time indexes: available
- status: `unknown` for all 14 because the legacy records have no terminal status
- legacy SHA-256: `a62065012356ede4a521cc34299bc90b514e9a285471e7184a4b366024178bfd`

## Validation Finding

The first installation smoke check found that `server/ops-wrapper` inserted
runtime candidates in reverse priority: an older compatibility runtime could
override the newly installed sibling runtime. That pre-matrix attempt failed in
argument parsing, before an audit file or business side effect existed. The
entrypoint now guarantees this priority:

```text
GUARDEDOPS_SRC
-> wrapper sibling runtime
-> compatibility fallback runtimes
```

A regression test covers both explicit and sibling runtime selection. The
latest wrapper was reinstalled before the audited matrix began.

## Cleanup Checks

- Existing demo wrapper SHA-256 before and after: `127cd8b2bb2af2f8299f77b5dd5b8f1e0a3b7d1c7621aa7a10ca5d9dd2262070`.
- Existing demo policy SHA-256 before and after: `bfe946dd628d06b5ee25f641beb200e027139e38786cf9a98ca713136c0d81d1`.
- Existing demo audit remained at 14 lines.
- `guardedops_demo.service` remained `not-found`; supervisor reported `no such process`.
- All three run-specific validation directories were absent after cleanup.

## Residual Risk

This milestone proves that, under the tested conditions, operations reaching
the wrapper produce decidable audit evidence, and that the tested write paths
fail closed when their start record cannot be persisted. It does not prove that
all operational intent reaches the wrapper. Root writes, direct SSH commands,
external release systems, hook bypasses, errors inside an allowlisted action,
and defects in the wrapper or policy can still escape this evidence boundary.

The next reliability phase must reconcile real wrapper audit records, hook
denials, and the complete set of write intents. Only that coverage data can
separate constraint-system effectiveness from low exposure or luck over the
previous production period.

## Verdict

Under the tested conditions, wrapper-managed operations have decidable audit
evidence. This report does not claim that GuardedOps covers every server write
or explains the absence of production incidents.
