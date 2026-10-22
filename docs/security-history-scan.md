# Historical secret-scan fixture review

Reviewed on 2026-10-22 with official Gitleaks 8.24.3. The three additions to
`.gitleaksignore` identify deliberate synthetic fixtures by exact commit, path,
rule and line. The scanner configuration and upstream default rules are unchanged.
Matched token-shaped values are omitted from this report.

| Historical finding | Evidence for synthetic classification |
| --- | --- |
| `a5d9905b6bca9ebe12806535a3271249aaf9b0ab:src/angerona/core/tool_analysis_jobs.py:github-pat:480` | `check_runtime` supplies a fixed alphabet-and-digits byte sample to the Gitleaks readiness job and requires the expected detection. The sample is scanner input; the code does not use it for authentication. |
| `dca1dacebb940f50a31d989f75ac59ffb9ce1532:tests/test_cycle4_round2_cloud_privacy.py:stripe-access-token:55` | `test_enabled_cloud_receives_only_recursive_redacted_bounded_prompt` supplies a fixed alphabet-and-digits sample to a capture-only fake cloud provider and asserts its removal from the outbound prompt. |
| `a2f99747395ef315898ff1f7d26b10c752837736:tests/test_cycle4_round2_cloud_privacy.py:generic-api-key:55` | An earlier form of the same privacy test uses a deterministic sample with the same fake-provider and outbound-redaction assertions. |

Classification used the committed fixture definitions and their consumers. No
credential was submitted to a service for validation. The new exemptions apply
only to these three fingerprints; no path, value or rule suppression was added.

## Coverage and validation

The initial 180-second ancestor scan was incomplete. A later attempt also
reported partial coverage because Git for Windows invoked an unavailable external
PDF text converter. Both attempts and their redacted findings remain preserved as
incomplete evidence. Disabling external diff drivers and text conversion for the
scan completed the raw committed-text ancestry review and produced these three
findings before the proposed exemptions.

The proposed ignore file then passed a full reachable-ancestry scan of
`cd8e22a302a18a92f3b38f0039272acb54b9f979`, with native exit code 0:
205 reachable commits, 204 commits with additions scanned, approximately
25.93 MB. The scope excluded other refs and uncommitted filesystem contents.
The command, run from that revision's checkout with the proposed ignore file,
was:

```text
gitleaks git --redact --config .gitleaks.toml --gitleaks-ignore-path .gitleaksignore --log-opts="--no-ext-diff --no-textconv cd8e22a302a18a92f3b38f0039272acb54b9f979" .
```

A separate disposable Git repository with no remotes used the unchanged scanner
configuration and exact proposed ignore file. All five negative controls were
detected, giving the expected native exit code 1:

- Each of the three historical samples in a new commit at its original path and
  line.
- The scanner-readiness sample at a different path.
- A newly generated, unrelated token-shaped sample at the scanner-readiness path.

These controls establish that the exact historical fingerprints do not exempt
new occurrences or unrelated material. Redacted reports and scope metadata were
kept outside the checkout. This result establishes coverage for the named
revision and scanner rules; later revisions require their own scan.
