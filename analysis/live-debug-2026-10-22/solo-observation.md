# Completed individual sensor observations

The `v114-solos-r5` run completed all 15 selected cases serially, under
concurrent offline-regression load. Each case used a fresh ordinary-user
profile, retained a stable first-party source manifest, proved the actual
core's identity and exit, and exited natively with code 0. No worker or
supervisor error, pending shutdown, or capture/export/scanner drop was reported.
The requested observation interval was 60 seconds per case; startup and cleanup
are additional. These are bounded observations, not clean-host or efficacy
claims. Other 72 capabilities remain held for individual active-path audit.

| Case | Final reported health | Interpretation |
| --- | --- | --- |
| Raw scanner | Separate authenticated scanner heartbeat | Normal exit; observer timing gap requires review as described below. |
| Process Monitor | 70 | Incomplete identities remain a coverage gap. Temporary test-tool notices have known development context, without blanket path exclusions. |
| LSASS Credential-Access Guard | 70 | Some process command lines and identities were unreadable. |
| Network Monitor | 100 | Complete reported inventory; observer timing exceeded two seconds. |
| SpywareGuard | 85 | Preview and per-source/adapter limitations remain; persistence observations did not claim confirmed spyware or response authority. |
| Sysmon Event Bridge | 100 | Cursor generation and exact record anchor verified; no reported case gap. |
| Self-Integrity Monitor | 60 | Fresh TOFU baseline remains explicitly unapproved; all 31 mandatory functions were watched. |
| C2 Beacon Detector | 100 | Complete reported snapshot, no flagged pattern and no reported case gap. |
| In-Memory Flight Cache | 100 | Observer timing gap; no reported cache loss. |
| Deterministic Fast-Path Interceptor | 100 | No reported case gap. |
| Evidence Lattice Fusion | 100 | No supplied active entities/findings and no reported case gap. |
| Identity Session Guard | 70 | Awaiting structured identity evidence; optional direct collectors were disabled. |
| Immutable Recovery Assurance Guard | 15 | Missing recovery evidence and assurance requirements remain a serious exposure. |
| AegisPath Exposure Graph Guard | 20 | No supplied graph snapshot; reachability remains unknown. |
| Fleet Health Monitor | 35 | No bound Fleet Fabric store in the isolated manager profile. |

The three HIGH/CRITICAL records were the missing-recovery exposure, unavailable
graph health and unbound-store Fleet health. The retained exported views report
verified original-event integrity; those redacted views remain advisory. Source
review confirms the current exposure/health contracts. Missing recovery or
collection evidence is not dismissed as a false positive, and no such warning
establishes an active intrusion or grants remediation authority.

The original raw-scanner result says `OBSERVED`, but the review must interpret
it as `OBSERVED_WITH_GAPS`: its final observer persistence stage took 65.436
seconds and crossed the requested deadline. Recorded observation lasted 95.360
seconds, while the start-to-start heartbeat maximum stayed at 0.547 seconds
because there was no next loop iteration. Original artifacts are preserved.
OBS-01 tracks correction of terminal-step, deadline-overrun and persistence
completion accounting.

The largest measured delays were in observer persistence rather than cached
module-view work. That locates a measurement cost; it does not identify the
storage, antivirus or scheduler cause, or explain historical Qt stalls. A
separate three-write probe measured explicit fsync at 89–214 ms, with private
creation at 1–13 ms and replacement below 1 ms. It does not explain the earlier
65-second wait. Only the observer's disposable heartbeat is a candidate for
non-durable persistence; plan/result and security-journal flush requirements
remain separate.

Next runtime comparisons are the selected interaction pairs, a longer combined
sensor/scanner repeat after observer correction, and native desktop/Black Box
observations. The [interaction map](interaction-map.md),
[issue register](README.md) and [validation record](validation.json) retain the
current scope and unresolved evidence.
