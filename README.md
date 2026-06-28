# GuardedOps

GuardedOps is a small framework for safer operational workflows. It gives
engineers and agents a planned, authorized, auditable path for production-like
changes without relying on open-ended remote shell access.

The first public version includes:

- `opsctl`: fleet-aware status, config planning, guarded apply, deploy plan, and rollback records.
- `ops-wrapper`: a restricted server-side command wrapper with redaction and policy checks.
- `routectl`: mockable route and SSH preflight helpers for public examples.
- `ops-guard-hook`: a local command guard that blocks raw production SSH patterns.
- `ops-review`: synthetic session review helpers for finding unsafe operational patterns.

All examples are synthetic. Do not place real hostnames, IPs, account names,
proxy profiles, logs, sessions, or secret-like values in this repository.

## Quick Start

GuardedOps v0.1 is a repo-checkout alpha. The Python package installs the CLI
entrypoints, while the public examples, wrapper script, and policy files are
used from this checkout.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e .

opsctl status --host staging
opsctl plan-config --host staging --file config/app.env --set APP_LOG_LEVEL=debug
opsctl apply-config --host staging --change-id <change-id> \
  --approval-token "host=staging action=apply-config change_id=<change-id>"

python server/ops-wrapper --policy server/policy.example.json host-observe
routectl doctor
routectl acceptance
ops-review collect --input examples/session-review/sessions --output .guarded_ops/review
scripts/leak_scan.sh --public .
```

## Safety Model

GuardedOps is designed around four ideas:

- Plan before apply.
- Authorize with exact action tokens. In v0.1 these are illustrative
  exact-match approvals; add expiry, nonce, and an external approval system
  before adapting the pattern to real privileged operations.
- Keep remote capabilities narrow and policy-driven.
- Review operational sessions using synthetic or explicitly provided input only.

See `docs/threat-model.md` for the public boundary and non-goals.
