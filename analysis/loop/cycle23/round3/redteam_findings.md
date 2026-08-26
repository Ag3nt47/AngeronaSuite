# Cycle 23 Round 3 — Red-Team Findings

Date: 2026-08-26  
Mode: authorized, actor-neutral defensive secure-code review; benign local
fixtures only; no web research and no live host/network/security-control changes

## Outcome

One new reproducible defensive-continuity weakness remains: **one Medium**.
No Critical, High, Low, or Info finding was opened. The combined SSH, audit-log,
independent-freshness, Personal Sentinel, live-activity, and Defense Memory
surfaces otherwise converged under this review. No new code-execution, secret,
raw-telemetry egress, TLS/pinning, response-authority, or hidden-reasoning
exposure was reproduced.

| Severity | New findings |
|---|---:|
| Critical | 0 |
| High | 0 |
| Medium | 1 |
| Low | 0 |
| Info | 0 |

## R3-01 — A newly observed physical path advances only the in-memory baseline

- **Severity:** MEDIUM
- **Component:** `src/angerona/modules/network_trust_monitor.py:1063-1160`;
  `src/angerona/core/network_trust.py:760-868`
- **Status:** OPEN

### Description

After a network baseline has reached `trusted`, `_tick()` persists neither a
new revision nor a provisional transition when a previously unseen Wi-Fi or
Ethernet path appears. `evaluate_network_trust()` has no path-added drift rule:
the new path has no prior fingerprint, so `historical_drift` remains false.
The final trusted-state branch then assigns the enlarged `result.baseline` to
`self._persisted_baseline` **in memory only**. The authenticated cursor/epoch
pair remains on the earlier path set.

A benign temporary-directory fixture reproduced the full transition:

1. Two complete, stable observations of one synthetic Ethernet path produced a
   trusted authenticated pair at revision 2 with one path.
2. A second complete synthetic Ethernet path was added and one tick ran.
3. The in-memory baseline contained two paths, while the authenticated file
   remained revision 2 with one path.
4. A fresh module instance loaded only the original path. Evaluating the same
   two-path snapshot after restart produced no `*_drift` finding.

Observed values were:

```text
disk_revision_before=2
disk_revision_after_new_path=2
disk_paths_after_new_path=1
in_memory_paths_after_new_path=2
restart_loaded_paths=1
restart_drift_rules=[]
```

### Impact

A newly introduced or renamed physical adapter can become the session's
accepted comparison state without entering authenticated persistence. If the
process restarts, the path is unseen again, so its initial DNS, DHCP, route,
gateway, profile, and epoch values do not receive historical-drift treatment.
Angerona still labels the path untrusted, emits a generic path observation, and
grants no endpoint or response authority. Those controls limit impact, but the
restart-surviving drift continuity promised by the authenticated network
baseline is lost. This is Medium for the elevated single-host threat model,
consistent with the earlier restart-continuity class, and is not an access or
trust-authorization bypass.

### Recommendation

Treat a current physical path token absent from the authenticated baseline as
an explicit `network.path_added`/interface-set drift transition once enrollment
is established. Keep the last authenticated baseline as the comparison source;
do not silently replace `_persisted_baseline` in memory. Require an explicit
operator reconciliation policy, or a bounded provisional-then-stable policy,
before persisting the enlarged path set. Whichever policy is selected must save
the authenticated cursor/epoch pair through the existing CAS/high-water gate,
remain blocked when independent freshness is unavailable, and add a regression
for add-path → restart → changed-path behavior.

## Trust-boundary accounting

- R2-01 remains an honestly documented **DEFERRED dependency**, not a new
  finding. With no injected authority, local state is labeled
  `local-authenticity-only` and never independently fresh. With an unavailable
  injected authority, state is provisional/offline and advancement is blocked.
  The existing compact Personal Sentinel receipt is not represented as an
  independently administered monotonic authority.
- The fixed Windows audit provider/channel/event identities, staged generation
  anchors, bounded replay, SSH include/source/ACL handling, Windows OpenSSH
  retry lifecycle, consuming forwarding grammar, route-family completeness,
  pinned direct HTTPS transport, nonce/freshness checks, sanitized dashboard,
  and digest-pinned data-only Defense Memory showed no reproduced regression.
- `A-07` is **resolved** despite stale wording in `PRIOR_FINDINGS.md`:
  `shadow_shield.py` uses SHA-256 for the non-security path identifier.
- Older architectural residuals A-04, A-06, and R6-03 remain unchanged and
  out of this Cycle 23 finding set; no Cycle 23 regression was observed.

## Prior-status totals

| Prior set | Resolved/verified | Still open or deferred |
|---|---:|---:|
| Cycle 23 Round 1 and Round 2 findings | 14 | 1 deferred external authority |
| Explicit older-status checks | 1 (`A-07`) | 3 unchanged architectural residuals |

