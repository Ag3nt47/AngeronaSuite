# Longer combined and scanner observation

Two separate disposable-profile cases ran for ten minutes each on 22 October 2026.
Both actual cores and the supervising process exited normally with native
exit 0. All 445 first-party Python inputs stayed unchanged. Raw process
identities and captures remain private.

| Case | Observation | Retained records | Errors / pending workers / reported drops | Classification |
| --- | --- | --- | --- | --- |
| All 14 admitted observation sensors | 600.094s | 1,139 views, including 1,128 authenticated-at-export events | 0 / 0 / 0 | Observed with gaps |
| Raw scanner alone | 600.187s | 749 scanner records; 551 authenticated heartbeat observations | 0 / 0 / 0 | Observed with gaps |

The combined case preserved missing Fleet and exposure-graph providers,
unproven independent recovery, ordinary-user collection restrictions,
unapproved fresh integrity baselines and SpywareGuard preview coverage.
Interval tracking also retained Sysmon's two initial health 85 samples before
recovery to 100: the fresh profile had no prior durable cursor. No sampled
module interval reported evidence loss, a crash or stopped-worker state.

The three high/critical combined notices described missing exposure/Fleet
evidence and unmet recovery assurance. Each explicitly withheld response
authorization. They establish operational gaps, rather than an observed
compromise. Earlier unbound LSASS notices remain separately unresolved.

The observer's largest inclusive loop gaps were 3.844 s for the combined case
and 4.437 s for the scanner. The corresponding largest observer-work stages
were 2.736 s and 4.179 s with measured observer-thread CPU 0 s at that timer's
resolution; advisory heartbeat persistence accounted for 2.735 s and 4.178 s.
Those are instrumentation delays, with no established storage, antivirus,
kernel or scheduling cause. They do not establish a scanner deadlock or
explain historical Qt stalls. Removing advisory fsync did not eliminate all
filesystem waits. Durable evidence and custody records still use their
existing stronger contracts.

Concurrent full regression and other diagnostic work contributed load. These
runs establish bounded case completion and the stated observed outcomes;
they are not isolated performance benchmarks, whole-host coverage or
uninterrupted healthy collection. The other 72 capabilities remain held for
active-path review. No host response, external AI, external feed or new
mutation authority was enabled for these cases.

See the [interaction map](interaction-map.md), [solo review](solo-observation.md)
and [current validation record](validation.json) for related evidence and limits.
