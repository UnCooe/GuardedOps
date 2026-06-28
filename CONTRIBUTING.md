# Contributing

GuardedOps accepts changes that keep the public boundary synthetic and generic.

Before opening a pull request:

```bash
python -m unittest discover -s tests
scripts/leak_scan.sh --public .
scripts/release_gate.sh
```

Use example names such as `example-prod-us`, `deploy-user`, and
`203.0.113.10`. Never use real operational identifiers in tests or docs.

