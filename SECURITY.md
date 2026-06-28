# Security Policy

Do not submit real infrastructure data to this repository.

Forbidden public content includes:

- Real production or staging hostnames.
- Real public or private IP addresses, except RFC 5737 documentation ranges.
- Real usernames, SSH aliases, proxy profiles, or provider names.
- Real logs, audit files, session transcripts, or secret-like values.

Run the public release gate before publishing:

```bash
scripts/release_gate.sh
```

Report security issues privately through the repository security advisory flow
or by contacting the maintainers listed by the hosting platform.

