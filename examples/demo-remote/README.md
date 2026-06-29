# Demo Remote

This fixture is a local, public-safe remote target for the GuardedOps v0.2
lifecycle. It is intentionally synthetic and contains no real hostnames,
accounts, proxy profiles, secrets, or service data.

`opsctl init-demo --force` initializes a temporary git repository from this tree
under `.guarded_ops/demo-local/app` before lifecycle checks. Users can copy the
`demo-ssh` fleet entry and replace only the SSH alias and sandbox paths for
their own isolated host.
