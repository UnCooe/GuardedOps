# Threat Model

GuardedOps reduces accidental and agent-driven operational risk by replacing
open-ended shell access with planned, policy-checked entrypoints.

## In Scope

- Accidental raw SSH to protected hosts.
- Limited diagnostic probes to protected hosts; arbitrary raw file and log reads
  remain blocked and must use a guarded entrypoint.
- Config changes that bypass allowlisted keys.
- Deploys that do not name an exact revision.
- Remote wrapper actions that read outside allowed roots.
- Review reports that expose raw command text instead of hashes or templates.
- Missing evidence for wrapper-managed writes when declared intent and audit
  inputs are available.
- Declared hook blocks and external write evidence during offline
  reconciliation.

## Out of Scope

- Secrets management.
- A complete production authorization system. Approval records are local
  plan-bound evidence with a short expiry and one-time consumption; they are
  not expiring credentials or an external identity system.
- Cloud account discovery.
- Privilege escalation outside the configured wrapper.
- Protection against a malicious repository maintainer.
- Real network validation in the public examples.
- Identity or authenticity of the user-turn reference supplied to the hook.
- Real rollback correctness.
- Root or direct SSH bypass prevention when it avoids the configured wrapper
  and declared evidence sources.
- CI/CD evidence integration.
- Host file integrity or authenticity of arbitrary JSONL evidence files.
- Business correctness of an allowed operation.
- Proof that GuardedOps caused or prevented a production incident.

## Public Boundary

The public repository must contain only synthetic examples. Real deny lists and
organization-specific migration preflight rules belong in private automation,
not in this repository.

## Reliability Boundary

Audit reconciliation can support this claim only: for the supplied
host/window/run inputs, every known write operation was either explained or
classified as a gap according to the `guardedops.audit-reconcile/v1` report.

It cannot claim that undisclosed sources were observed. Hook and external
evidence are explicit files in the first version; ordinary JSONL does not prove
the producer, host integrity, or completeness of all side channels.

Operational reliability should therefore be evaluated with a 2-4 week
observation protocol: generate daily reports, save source inventory and input
hashes, track write exposure volume, and review weekly whether all declared
sources stayed healthy with zero gaps. Days with zero known writes are
insufficient exposure, not evidence of reliability.
