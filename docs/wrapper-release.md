# Wrapper Release

The public example wrapper is installed as `ops-wrapper`.

Example local smoke checks:

```bash
python server/ops-wrapper --policy server/policy.example.json version
python server/ops-wrapper --policy server/policy.example.json host-observe
python server/ops-wrapper --policy server/policy.example.json runtime-baseline
python server/ops-wrapper --policy server/policy.example.json log-query \
  --path examples/mock-app/logs/current.log --lines 20
python server/ops-wrapper --policy server/policy.example.json config-patch \
  --file config/app.env --set APP_LOG_LEVEL=debug --dry-run
```

Do not adapt `sudoers.example` blindly. It is a minimal example showing the
expected command shape only.

When running the wrapper with elevated privileges, keep the policy path fixed
to a root-owned file. The `--allow-untrusted-policy` flag exists only for local
tests and must not be included in privileged sudoers rules.
