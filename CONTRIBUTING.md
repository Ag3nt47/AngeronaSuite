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

## Optional verified developer toolkit

On 64-bit Windows, `tools\bootstrap_github_toolkit.ps1` downloads the exact
GitHub releases pinned in `tools\github_toolkit.lock.json`, verifies every
SHA-256 digest, and installs the tools under ignored `.dev-tools`. It provides:

- uv for fast isolated dependency setup;
- py-spy for an administrator-authorized live hang profile;
- hyperfine for repeatable benchmarks;
- official GitHub CLI for repository and pull-request workflow checks; and
- an isolated Bandit, Vulture, and pytest-timeout audit environment.

Run `tools\run_developer_toolkit.ps1 -Audit` for static evidence. Use
`-Benchmark -Command '<command>'` for a timed comparison or
`-Profile -TargetProcessId <pid>` to record a bounded SpeedScope profile of a
locally running Angerona process. These are contributor tools, not product
runtime dependencies.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).
Detection changes also follow
[Detection-content governance](docs/enterprise/DETECTION_CONTENT_GOVERNANCE.md).
Compatibility and architecture changes must remain consistent with
[the compatibility policy](docs/enterprise/COMPATIBILITY_POLICY.md) and
[accepted architecture decisions](docs/enterprise/ARCHITECTURE_DECISIONS.md).
