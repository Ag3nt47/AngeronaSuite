# Automatic runtime recovery

Angerona starts its runtime healer automatically after the status reporter
starts. Restart Angerona after updating to load it. No separate script, model,
scheduled task, or extra dependency is required.

Open **Black Box > Suite Health > Self-healing** to see worker recovery. The
same component states and recent actions appear under `runtime_healer` in the
configured data directory's `diagnostics/status.json`, with a readable summary
in `diagnostics/status.txt`. Black Box displays this information only when the
snapshot is fresh and identifies the current process. Black Box remains an
independent, read-only observer.

## What it repairs

| Fault | Automatic behavior |
| --- | --- |
| Status reporter thread exits | Starts one replacement reporter worker. |
| Diagnostics directory temporarily missing or unavailable | Retries the configured destination and recreates a missing directory; writes complete snapshots using atomic replacement. |
| Status writes fail or become overdue | Requests a fresh report on the reporter's worker, preserving the previous complete files when replacement fails. |
| Event recorder primary or overflow worker exits | Starts only the missing worker, preserving its live peer and the existing queues. |
| Protection module crashes or misses its declared deadline | The existing Watchdog Monitor remains responsible for generation-checked, bounded recovery. |
| Core or sidecar process exits | The existing process supervisors retain their authenticated recovery policy. |

The runtime healer samples its two application-owned services every 15 seconds,
or 60 seconds in Chill mode. It requires two consecutive unhealthy observations
before attempting repair. Attempts are charged before execution and separated
by monotonic backoff. There are at most three attempts per incident. Five
minutes of observed health are required before the attempt budget resets.
Unknown probe results cannot authorize a repair. Explicitly stopped services
stay stopped; the healer shuts down before the services it supervises.

`verifying` means a request was issued, not that the repair succeeded.
`stabilizing` means a subsequent health probe observed availability.
`attention_required` means the incident exhausted its attempts. Recent action
history retains up to 32 entries with timestamps, and cumulative failure
counters remain visible. This bounded history and these thread recovery budgets
are process-local; they are not an independent, durable audit ledger.

## Limits

Restored worker availability does not establish complete sensor coverage or
recover an event that was already lost before a worker died. Queued events and
the existing authenticated overflow/replay path remain intact. The healer
does not terminate a live or blocked thread, reset a database, erase historical
errors, or clear an authenticated cursor, outbox, signing key, or recovery state.

A quiet event bus is normal: delivery is inline and there is no dispatcher
heartbeat. Callback failures and delivery-budget overruns remain advisory;
the healer never removes a subscriber or fabricates bus traffic to make its
health display green. It never treats log text or diagnostic JSON as commands.

Missing Ollama dependencies, unapproved models, Defender custody failures,
damaged trust state, software defects, and resource exhaustion still require
the appropriate diagnosis. HEAL continues to stage proposed source-code fixes
for review. The runtime healer does not download software, enroll models,
change security policy, or modify running source code. Diagnostic path repair
refuses symbolic links, junctions/reparse points, and hardlinked destinations;
it does not loosen permissions when a path is denied.
