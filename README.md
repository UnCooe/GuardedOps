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

## Agent Quick Start

GuardedOps v0.2 is meant to be used from a source checkout. In the common agent
workflow, a user asks Codex or another coding agent to clone this repository and
run the local demo lifecycle before adapting anything to a real environment.

Prerequisites:

- Python 3.11 or newer.
- Git available on `PATH`.
- A repository checkout. The examples, wrapper script, policy files, and release
  checks are intentionally kept in this repository instead of being packaged as
  standalone runtime data.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .
```

## Local Demo

Start here. The `demo-local` host runs entirely inside `.guarded_ops/demo-local`
and does not require SSH, production hosts, secrets, or organization-specific
configuration.

```bash
opsctl init-demo --force
```

Run the guarded lifecycle against the isolated demo workspace:

```bash
opsctl baseline --host demo-local

opsctl git --host demo-local --op fetch --remote origin \
  --approval-token "host=demo-local action=safe-git-fetch remote=origin"

exact_sha="$(git -C .guarded_ops/demo-local/app rev-parse HEAD)"
opsctl git --host demo-local --op checkout --ref "$exact_sha" \
  --approval-token "host=demo-local action=safe-git-checkout ref=$exact_sha"

opsctl plan-config-batch --host demo-local --file config/app.json \
  --set feature.enabled=true \
  --set limits.timeout_ms=2500
```

Copy the `change_id` from the plan output, then apply it with the exact approval
token shown by the plan:

```bash
opsctl apply-config-batch --change-id <change-id> \
  --approval-token "host=demo-local action=apply-config-batch change_id=<change-id>"

opsctl restart-service --host demo-local \
  --approval-token "host=demo-local action=restart-service service=guardedops-demo"

opsctl logs --host demo-local --name current.log
```

The local demo proves the intended shape of the system: plan first, require exact
approval tokens for risky actions, mutate only allowlisted config keys, write an
audit/backup record, restart only the configured demo service, and return
structured output for verification.

## SSH Sandbox

After the local demo works, adapt only the `demo-ssh` fleet entry to an isolated
sandbox host. Do not point validation at an existing application path or service.
The public SSH sandbox contract is:

```text
app: /opt/guardedops-demo/app
bare repo: /opt/guardedops-demo/origin.git
wrapper: /usr/local/bin/ops-wrapper-demo
policy: /etc/guardedops-demo/policy.json
audit: /var/log/guardedops-demo/audit.jsonl
backup: /var/backups/guardedops-demo
service: guardedops_demo
```

Representative bootstrap:

```bash
opsctl --dry-run install-wrapper --host demo-ssh
opsctl install-wrapper --host demo-ssh
opsctl --dry-run init-ssh-demo --host demo-ssh --reset
opsctl init-ssh-demo --host demo-ssh --reset
opsctl restart-service --host demo-ssh \
  --approval-token "host=demo-ssh action=restart-service service=guardedops_demo"
```

Keep the sandbox boundary strict: operators and agents should verify only the
paths above while validating GuardedOps itself.

## Route And Review Helpers

These helpers are synthetic and safe to run from the checkout:

```bash
routectl doctor
routectl acceptance
ops-review collect --input examples/session-review/sessions --output .guarded_ops/review
```

For the v0.2 end-to-end lifecycle target and sandbox validation contract, see
`docs/e2e-deployment-lifecycle.md`.

## Release And Package Boundary

Use the release gate when preparing a public repository state, not as the final
step of the demo walkthrough. The demo and review commands create `.guarded_ops`,
so remove generated state before running the leak scan or release gate:

```bash
rm -rf .guarded_ops build dist src/guardedops.egg-info
python -m unittest discover -s tests
scripts/release_gate.sh
```

The Python package installs CLI entrypoints (`opsctl`, `routectl`, `ops-review`,
and `ops-guard-hook`). It does not package the public examples, wrapper script,
policies, or release scripts as standalone runtime data. For v0.2, the supported
agent-first experience is clone the repository, install editable, and run the
checkout-backed demo lifecycle above.

## Safety Model

GuardedOps is designed around four ideas:

- Plan before apply.
- Authorize a frozen plan with an exact action token or a local approval record.
  Approval records bind a plan hash to a recorded user turn, expire after 15
  minutes, and can be consumed only once. They provide local evidence of the
  approval flow, not an external identity or privileged authorization service.
- Keep remote capabilities narrow and policy-driven.
- Review operational sessions using synthetic or explicitly provided input only.

The approval-record flow is available through `opsctl approve-plan` and the
optional `hooks/ops_approval_prompt.py` hook. The hook records only hashes and
metadata; it never persists the user's raw prompt. Legacy exact-match tokens
remain supported for the demo and compatibility paths.

See `docs/threat-model.md` for the public boundary and non-goals.
