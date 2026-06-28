# Route Preflight

`routectl` provides a mockable route interface for public examples.

```bash
routectl doctor
routectl preflight --target example-prod-us
routectl proxycommand --target example-prod-us --print-json
routectl sync-ssh-config --output /tmp/guardedops-example-ssh.conf --dry-run
routectl git --operation ls-remote
routectl acceptance
routectl matrix --regions us,eu -- ssh example-prod-us true
```

The public example does not connect to real networks. Real proxy profiles,
provider names, SSH aliases, and server IPs must stay outside the public repo.
