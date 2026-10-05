# E2E Deployment Lifecycle

GuardedOps v0.2 is a reference implementation for AI-safe operational
workflows. It is not a cloud deployment platform and it does not include any
organization-specific SOP. The public contract is a small set of guarded
operations that can be configured for a local demo target or an isolated SSH
host.

## Lifecycle

The target lifecycle is:

```text
install-wrapper
-> observe / runtime-baseline
-> safe-git fetch
-> safe-git checkout exact ref
-> plan-config-batch
-> apply-config-batch
-> restart-service
-> logs / runtime-baseline verification
-> audit-status verification
-> rollback when needed
```

Local `opsctl` owns planning, exact approval checks, and transport. Remote
`ops-wrapper` owns the actual filesystem, git, config, service, audit, and
baseline operations.

## Local Demo

The `demo-local` fleet host runs without SSH against `examples/demo-remote/app`.
It is intentionally synthetic so a new user can run the lifecycle from a repo
checkout before adapting the `demo-ssh` template to a real host.
Run `opsctl init-demo --force` first; it copies the fixture into an isolated
`.guarded_ops/demo-local/app` git workspace so lifecycle commands do not mutate
the GuardedOps repository checkout.

The local demo must prove:

- exact approval tokens are required for high-risk operations
- git checkout and deploy use exact hex refs, not branch names
- config changes are limited to allowlisted keys
- config apply writes a backup and audit record
- restart affects only the configured demo service
- logs and baseline return structured, redacted output
- audit-status reports complete evidence for the run

## Server Sandbox

Real-host validation must use an isolated sandbox only:

```text
app: /opt/guardedops-demo/app
bare repo: /opt/guardedops-demo/origin.git
wrapper: /usr/local/bin/ops-wrapper-demo
policy: /etc/guardedops-demo/policy.json
audit: /var/log/guardedops-demo/audit.jsonl
backup: /var/backups/guardedops-demo
service: guardedops_demo
```

Do not modify, read, probe, or restart existing application paths or services
while validating the GuardedOps public lifecycle. Operators should verify only
the allowlisted demo paths above; checking organization-owned paths or service
states is outside the public validation contract.

## Acceptance Commands

Local release validation:

```bash
python --version  # must be 3.11+
python -m pip install --upgrade pip
python -m unittest discover -s tests
scripts/release_gate.sh
```

Representative local lifecycle commands:

```bash
opsctl init-demo --force
opsctl baseline --host demo-local
opsctl git --host demo-local --op fetch --remote origin \
  --approval-token "host=demo-local action=safe-git-fetch remote=origin"
opsctl git --host demo-local --op checkout --ref <exact-sha> \
  --approval-token "host=demo-local action=safe-git-checkout ref=<exact-sha>"
opsctl plan-config-batch --host demo-local --file config/app.json \
  --set feature.enabled=true
opsctl apply-config-batch --change-id <change-id> \
  --approval-token "host=demo-local action=apply-config-batch change_id=<change-id>"
opsctl restart-service --host demo-local \
  --approval-token "host=demo-local action=restart-service service=guardedops-demo"
opsctl logs --host demo-local --name current.log
opsctl audit-status --host demo-local --run-id <run-id>
```

Representative SSH sandbox bootstrap:

```bash
opsctl --dry-run install-wrapper --host demo-ssh
opsctl install-wrapper --host demo-ssh
opsctl --dry-run init-ssh-demo --host demo-ssh --reset
opsctl init-ssh-demo --host demo-ssh --reset
opsctl restart-service --host demo-ssh \
  --approval-token "host=demo-ssh action=restart-service service=guardedops_demo"
opsctl audit-status --host demo-ssh --run-id <run-id>
```

Audit verification uses the shared summary contract in `docs/audit-contract.md`.
Exit `0` means the evidence is complete; exit `3` means partial evidence needs
review; exit `2` means the source or transport was insufficient.
