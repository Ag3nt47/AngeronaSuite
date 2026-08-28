# Cycle 25 / Round 3 — Final adversarial closure

Date: 2026-08-28
Product target: 1.12.0

## Outcome

The final adversarial recheck found no open High or Critical code finding in the
v1.12 change set. Twelve closure checks produced bounded fixes or confirmed
truthful residual labels. They are verification lineages, not a new unique-
vulnerability count.

| Closure check | Result |
| --- | --- |
| Auto Adapt accepted-choice race and overlapping operations | Choices are copied into immutable worker values; only one operation can be in flight; controls and tooltips expose unavailable prerequisites. |
| Recovery enrollment/apply boundary | Enrollment is explicit and non-replaceable; apply refuses before mutation without a complete baseline; exact plan approval is separate. |
| Remote-session anti-lockout | Fresh host-wide checks include bounded WTS session enumeration, SSH/current-session evidence, and bounded common third-party remote-control agent process inspection. Unknown/error states do not authorize mutation. |
| Typed row sorting | Severity and risk values sort by typed rank/numeric value rather than display text. |
| Alert identity and details | Stable exact record identity controls dedupe/queueing; empty selections clear; deterministic fingerprints are not labeled authentic unless HMAC verification actually occurred. |
| Alert analysis overload | At most two analyses run and six exact event identities queue; duplicates do not consume additional slots. |
| Temporary suppression | Only the exact confirmed rule is suppressed for 15 minutes, with visible audit and Undo; integrity alerts cannot use the path. |
| SOAR history clearing | Clear is an atomic recoverable archive with a digest manifest; restore refuses overwrite. The digest is not described as an independent signature. |
| CVE detail lifecycle | Detail work is owned, interruption-aware, and nonblocking. A global distinct-CVE worker cap remains proposed. |
| Settings transaction | Settings bytes, protected credentials, environment projection, and autostart compensate on a later failure; composite rollback failure stays explicit. |
| Standards truth | ATT&CK 19.2, Navigator 5.3.2/layer 4.5, constrained OCSF 1.8, and constrained Sigma atomic receipts passed focused regressions. |
| IPC legacy residue | Plaintext legacy key residue is checked and removed even when the protected-store key already exists; unavailable secure storage fails closed. |

## Residuals accepted for release

- The recovery baseline is complete for Windows Firewall policy only, not the
  operating system, services, hardware, ports, applications, or network devices.
- WTS/process/SSH checks are best-effort operating-system evidence and cannot
  enumerate an unknown remote-control mechanism or survive privileged sensor
  compromise.
- The SOAR archive manifest detects accidental mismatch; it is not an
  independently witnessed anti-rollback receipt.
- Outbox deletion/whole-database rollback, at-least-once duplicates, restart-
  epoch key coordination, full OCSF/Sigma compatibility, and IPC production
  transport remain explicit boundaries.
