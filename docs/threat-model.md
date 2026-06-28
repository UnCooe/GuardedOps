# Threat Model

GuardedOps reduces accidental and agent-driven operational risk by replacing
open-ended shell access with planned, policy-checked entrypoints.

## In Scope

- Accidental raw SSH to protected hosts.
- Config changes that bypass allowlisted keys.
- Deploys that do not name an exact revision.
- Remote wrapper actions that read outside allowed roots.
- Review reports that expose raw command text instead of hashes or templates.

## Out of Scope

- Secrets management.
- A complete production authorization system. v0.1 approval tokens are
  illustrative exact-match tokens, not expiring credentials.
- Cloud account discovery.
- Privilege escalation outside the configured wrapper.
- Protection against a malicious repository maintainer.
- Real network validation in the public examples.

## Public Boundary

The public repository must contain only synthetic examples. Real deny lists and
organization-specific migration preflight rules belong in private automation,
not in this repository.
