# Round 8 — Host Adaption Adversary Findings

Date: 2026-08-24. Scope: the new `HostAdaptationService`, Adaption workbench,
dashboard automation monitor, and Windows Firewall command boundary. This was a
defensive, source-level adversary pass; no real firewall policy was applied or
restored.

Five Medium findings were confirmed before remediation:

- **R8-RT-01 — stale automation authority.** A context worker could continue
  after the operator disabled auto-apply because configuration reads and the
  final mutation boundary were not revision-bound.
- **R8-RT-02 — command success was not a postcondition.** A zero PowerShell exit
  did not prove that the effective firewall state matched the plan, and recovery
  needed the same verification discipline.
- **R8-RT-03 — over-broad exception and feedback scope.** Category/key matching
  could suppress a changed anomaly, while repeated feedback could tune a whole
  category too quickly.
- **R8-RT-04 — context precedence could weaken posture.** A familiar SSID could
  outrank simultaneous Public-network evidence and select a less restrictive
  profile.
- **R8-RT-05 — incomplete collection could look authoritative.** Service and
  listener rows lacked enough stable identity, firewall rules were absent, and
  truncation or per-row failures were not consistently exposed to drift scoring.

## Recommended controls

Bind automation to a monotonic configuration revision and re-authorize at the
last mutation boundary; serialize apply and rollback; use trusted absolute
Windows tool paths and a sanitized child environment; verify the effective
ActiveStore after apply and restore; scope exceptions to exact finding
fingerprints; require distinct reviewed feedback; make the strongest matched
context win and never auto-relax; and attach explicit completeness metadata to
every bounded collector.

## External acceptance boundary

Real elevated firewall apply/rollback, connectivity-loss recovery, and a
physical simultaneous Public/Private/VPN topology remain operator-controlled
Windows acceptance tests. The adversary pass did not mutate the host.

