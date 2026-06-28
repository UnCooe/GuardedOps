# Architecture

GuardedOps has five cooperating parts:

- `opsctl` loads fleet configuration, creates plans, validates approval tokens,
  and records apply/deploy/rollback actions.
- `ops-wrapper` is a restricted server-side executable controlled by a JSON
  policy file.
- `ops-guard-hook` blocks unsafe local command shapes and points users to safe
  entrypoints.
- `routectl` validates synthetic route configuration and produces mockable
  preflight output.
- `ops-review` reads explicitly provided synthetic session files and reports
  operational patterns without exposing raw sensitive command text.

The public examples are local and synthetic so tests can run without SSH,
Clash, Mihomo, cloud credentials, or real production hosts.

GuardedOps v0.1 is intentionally a repo-checkout alpha. The wheel verifies the
Python CLI entrypoints, but example policies, wrapper scripts, docs, and
synthetic fixtures are published as repository files rather than package data.
