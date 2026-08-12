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

The audit and reconciliation layer is shared across these entrypoints:

- `guardedops.intent/v1` records a write intent before `opsctl` runs a supported
  wrapper-managed write (`apply-config-batch`, `deploy-ref`, `restart-service`,
  or `safe-git` fetch/checkout). The intent uses the exact `operation_id` that the remote wrapper must
  reuse.
- `guardedops.audit/v1` records wrapper start/result events for that same
  operation ID.
- `guardedops.evidence/v1` allows explicit hook block or declared external
  write evidence to be included in offline reconciliation.
- `ops-review audit-reconcile` evaluates the declared input files.
- `ops-review daily-evidence` renders a reconciliation JSON report into daily
  JSON and Markdown artifacts.

Reconciliation uses exact operation IDs, not fuzzy host/action/run matching.
Its known write denominator is the union of write intents, wrapper write audit
operations, hook blocks, and declared external write evidence. Zero known writes
means insufficient exposure. Missing sources are insufficient. Gaps, duplicate
operation IDs, malformed records, legacy records, or metadata conflicts produce
a partial result.

The public examples are local and synthetic so tests can run without SSH,
Clash, Mihomo, cloud credentials, or real production hosts.

The JSON reconciliation report is the authoritative artifact. Markdown daily
evidence is a safe summary render only.

GuardedOps v0.1 is intentionally a repo-checkout alpha. The wheel verifies the
Python CLI entrypoints, but example policies, wrapper scripts, docs, and
synthetic fixtures are published as repository files rather than package data.
