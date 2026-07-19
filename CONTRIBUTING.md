# Contributing

Keep changes defensive, local-first, and testable. Do not add offensive payloads,
credential theft, destructive persistence, covert collection, or unbounded
network listeners.

Before proposing a change:

1. Create a focused branch and avoid committing runtime state or local secrets.
2. Run `python -m compileall -q src tests` and `python -m pytest -q`.
3. Add a deterministic self-test for new modules and a regression test for bug
   fixes. Tests must not contact the network, download models, or mutate the host.
4. Document new egress, elevation, retention, and remediation behavior.
5. Keep optional integrations off by default, authenticate peers, bound inputs,
   and require an explicit operator confirmation for state-changing actions.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
