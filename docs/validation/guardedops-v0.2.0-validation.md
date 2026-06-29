# GuardedOps v0.2.0 Validation Report

Validated at: 2026-06-29T11:41:28Z

## Baseline

- Tag: `v0.2.0`
- Final commit: `16de003a4d227c9c315b1748c28cee8b0ac21dbd`
- Scope: local demo lifecycle, independent subagent review, real SSH sandbox lifecycle on `aiserver-test` and `aiserver-pre`

## Local Gates

- `python -m unittest discover -s tests`: pass, 37 tests
- `scripts/release_gate.sh`: pass
- Local `demo-local` lifecycle: pass

## Subagent Validation

- New user local clone simulation: pass
  - Confirmed clone, install, `init-demo`, baseline, fetch, exact SHA checkout, config batch, restart, logs.
  - Negative coverage included branch checkout rejection and approval failures.
- Independent security review:
  - First review found blocking issues in exact ref handling, secret redaction, legacy config write path, and approval scope strictness.
  - Follow-up review found duplicate approval keys were still accepted.
  - Final review passed with no P0/P1 findings.
- `aiserver-test` real sandbox:
  - Initial run passed the lifecycle but violated the validation boundary by read-only probing business paths/services.
  - Guardrails were tightened, and the rerun passed without reading or touching business paths/services.
- `aiserver-pre` real sandbox:
  - Passed the same lifecycle under the strict demo-only boundary.
- Fresh clone SSH smoke on `aiserver-test`:
  - Passed after adding first-class `init-ssh-demo`, Python/pip docs, and avoiding remote temp files.

## Real Sandbox Evidence

Allowed remote paths only:

- `/opt/guardedops-demo`
- `/etc/guardedops-demo`
- `/usr/local/bin/ops-wrapper-demo`
- `/var/log/guardedops-demo`
- `/var/backups/guardedops-demo`

Validated lifecycle:

```text
install-wrapper
-> init-ssh-demo
-> version / baseline / observe
-> safe-git fetch
-> branch checkout negative
-> exact SHA checkout
-> config batch plan/apply
-> wrong/extra/duplicate approval negatives
-> restart mock service
-> logs / final baseline
-> audit and backup verification
```

Representative evidence:

- `aiserver-test`: final app HEAD `b6a42aef7ddad69a45cb0a55f8afc93b770b3f47`, backup under `/var/backups/guardedops-demo`, restart log under `/opt/guardedops-demo/app/logs/current.log`.
- `aiserver-pre`: final app HEAD `a932c3508642c8f056c53d478a7404091b644d35`, backup under `/var/backups/guardedops-demo`, restart log under `/opt/guardedops-demo/app/logs/current.log`.

## Fixes Driven By Validation

- Isolated `demo-local` into `.guarded_ops/demo-local/app` so local lifecycle cannot act on the GuardedOps repo checkout.
- Hardened exact ref handling so hex-like branch/tag names cannot be used as checkout/deploy targets.
- Redacted secret-like values in config batch plan output and wrapper diff output.
- Disabled non-dry-run legacy `ops-wrapper config-patch`; config writes must use approved batch apply.
- Made approval tokens strict: no missing, extra, or duplicate keys.
- Preserved demo policy audit/backup paths under `/var/log/guardedops-demo` and `/var/backups/guardedops-demo`.
- Added `init-ssh-demo --reset` to initialize only the configured SSH demo sandbox paths.
- Streamed demo fixture over SSH without writing remote temp files.
- Documented Python 3.11+ and pip upgrade requirements.
- Clarified that validation must not read, probe, or restart organization-owned application paths/services.

## Remaining Risks

- `init-ssh-demo` is intentionally demo-only. A real user still needs to adapt the fleet/policy for their own sandbox.
- SSH demo bootstrap still requires SSH and filesystem permissions for the configured demo paths.
- Error output is stderr text, not structured JSON.
- Per-action duplicate approval tests are not exhaustive, but all high-risk actions share the same approval parser.

## Verdict

GuardedOps v0.2.0 is usable as a public, configurable AI-safe ops workflow reference implementation with a real local and SSH sandbox lifecycle. It is not a general cloud deployment platform and does not include business SOP.
