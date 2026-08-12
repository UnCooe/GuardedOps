# GuardedOps Write Intent Reconciliation Validation Report

Validated at: 2026-08-12T13:30:21Z

## Scope

- Milestone: `guardedops.intent/v1`, `audit-reconcile`, and `daily-evidence`.
- Run id: `write-intent-20260812T131344Z`.
- Host identity inside the evidence contract: `validation-ssh`.
- Excluded: current-turn authorization, real rollback, root/direct-SSH bypass
  detection, external deployment-system coverage, and incident causality.
- Bootstrap was setup-only and outside the reconciliation denominator. The
  audited denominator contains only supported wrapper-managed write actions.

## Local Gates

- Independent contract and security tests: pass, including false-green,
  malformed input, metadata conflict, hook-only evidence, and redaction cases.
- `python -m unittest discover -s tests`: pass, 91 tests before report creation.
- `scripts/release_gate.sh`: pass before SSH validation, including public leak
  scans and package builds.
- `git diff --check`: pass.
- Independent reviewer: no P0 or P1 findings. Its remaining equals-form command
  redaction P2 was fixed and covered by a regression test.

The SSH install dry-run found one additional integration defect before the
write matrix: `install-wrapper` places runtime code beside the wrapper under
`src/`, but the entrypoint did not search that exact layout. A black-box test
reproduced the failure, the entrypoint was fixed, and the full suite passed
before remote writes began.

## SSH Boundary

All remote state was confined to these run-specific directories and removed
after evidence capture:

- `/opt/guardedops-demo/validation/write-intent-20260812T131344Z`
- `/var/log/guardedops-demo/validation/write-intent-20260812T131344Z`
- `/var/backups/guardedops-demo/validation/write-intent-20260812T131344Z`

`init-ssh-demo --reset` was not used. The fixture was initialized only inside
the run-specific app directory. The validation policy used the mock service
adapter; no systemd or supervisor service was created, changed, or restarted.

## Command Matrix

| Case | Expected | Observed | Correlation |
| --- | --- | --- | --- |
| `host-observe` | isolated read succeeds | exit 0 | read audit success |
| `runtime-baseline` | isolated read succeeds | exit 0 | read audit success |
| allowed config batch | config and backup change | exit 0 | exact intent + start/success |
| mock restart | sandbox status/log change | exit 0 | exact intent + start/success |
| exact-SHA checkout | detached checkout succeeds | exit 0 | exact intent + start/success |
| disallowed fetch | blocked by policy | exit 2 | exact intent + policy_denied |
| repeated disallowed fetch | blocked with state unchanged | exit 2 | exact intent + policy_denied |

The complete app-tree hash immediately before and after the repeated denied
fetch was identical:

```text
a045e712213efa56c003df2048fa84415abc8de0f5def26e018cdd63ed4989c1
```

## Reconciliation Evidence

The server-side audit summary reported:

- verdict: `complete`, exit 0
- audit records: 10
- normalized operations: 7 total, 2 read and 5 write
- write success: 3
- policy denied: 2
- incomplete, orphan, invalid, malformed, unknown: 0

The offline reconciliation reported:

- verdict: `complete`, exit 0
- known writes: 5
- explained writes: 5
- coverage: 1.0
- intent records: 5
- wrapper success: 3
- wrapper failed / policy denied: 2 / 2
- missing intent, missing wrapper audit, metadata conflict, duplicate,
  incomplete, malformed, legacy, unknown: 0

Evidence artifact hashes before local generated-state cleanup:

- intent JSONL: `ef28b3b64653ad2f0e4bad88ea83fc657ead777ba13c2996e50de66bbaea9e86`
- pulled audit JSONL: `f9a521ec72e71ebe22eec045e28c8ecf826f1e3edb8ef674c5628ee404149578`
- reconciliation JSON: `e68b9f734c45b26d6414c064081c5315d2beb40a6c7cde3eb35af2ebce67a5ad`
- daily evidence JSON: `a22b15058e7293de37bc0bb77b2ab52f7e08686a362472e9235207e697dd3661`
- daily evidence Markdown: `08d8422b50fdf04bb9bd2ac553f25f1527c3e862ee9fb26111571fa943910f02`

A scan of the intent, audit, and reconciliation artifacts found no raw config
assignment, approval scope, bearer value, or unredacted approval argument.

## Cleanup Checks

- Existing demo wrapper SHA-256 before and after:
  `127cd8b2bb2af2f8299f77b5dd5b8f1e0a3b7d1c7621aa7a10ca5d9dd2262070`.
- Existing demo policy SHA-256 before and after:
  `bfe946dd628d06b5ee25f641beb200e027139e38786cf9a98ca713136c0d81d1`.
- Existing demo audit SHA-256 before and after:
  `a62065012356ede4a521cc34299bc90b514e9a285471e7184a4b366024178bfd`.
- Existing demo audit remained at 14 lines.
- Supervisor reported `guardedops_validation_mock` as `no such process`.
- All three run-specific validation directories were absent after cleanup.

## Residual Risk

This run proves that the five declared, wrapper-managed write attempts were all
exactly explainable by intent plus wrapper audit, including two policy blocks.
It does not prove that every real server write enters this evidence universe.
Wrapper installation/bootstrap, local legacy writes, direct root or SSH writes,
external delivery systems, and forged evidence sources remain outside this
milestone unless instrumented or supplied through a trusted evidence feed.

A single clean validation run also cannot distinguish system effectiveness from
low production exposure or luck. The next operational phase is a fixed 2-4 week
observation window that inventories every source daily, reconciles actual write
volume, and treats missing source health or zero exposure as non-green.

## Verdict

Under the tested SSH sandbox conditions, supported wrapper-managed writes have
exact, decidable intent-to-audit reconciliation. This is not a claim that
GuardedOps covers every production write or explains the absence of incidents.
