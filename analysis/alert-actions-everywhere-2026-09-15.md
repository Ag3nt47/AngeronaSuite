# Alert actions from every evidence view

## Report and cause

The operator opened an alert detail from outside the Live Alerts table and
clicked Allow. The dialog reported "Allow needs the live Alerts panel."
Only the inline Live Alerts opener supplied the panel argument. Event history,
module feeds/history, module resource details and the live-defense summary
created the same dialog without its action context. Their parent chain still
led to the same MainWindow, but the dialog never resolved that owner.

## Changes

- Alert Detail resolves its session's action owner through the complete widget
  parent chain. The Live Alerts tab can remain hidden. Detached bus-backed views
  can resolve only a session with the identical EventBus instance; they never
  select an arbitrary top-level window. Deleted or closing owners are rejected.
- Allow and Block invoke the same confirmation, scope, preflight and audit
  handlers as inline rows. The originating detail displays the actual result,
  including cancellation and refusal. Resolving the bus also allows existing
  HMAC-authenticity checks to run from these views.
- Detail includes Undo Allow for its own exact rule/pattern. It cannot
  accidentally revoke a later Allow on another alert. Open details update when
  a matching suppression is created, revoked or expires, including when the
  live feed is empty.
- Analyze uses the session's existing deduplication, two-worker/six-queued
  limits and explicit cloud setting. Progress, queue refusal, errors and results
  are sent to open details for that exact event. QObject signal connections
  disconnect when a detail is deleted; the shared worker may finish safely.
- Resolve Center uses the same session lookup and Allow meaning. It no longer
  turns Allow into permanent process trust or acknowledges an alert when the
  suppression confirmation is cancelled. Explicit Ignore remains separate;
  persistent process trust remains under Settings → Trusted Processes.

The session's AlertsPanel still owns shared suppression and analysis state;
the operator does not need to open or navigate to it. A detached record with no
active session does not offer an enabled suppression action. Existing
standalone analysis and review-only containment staging remain available.

Integrity alerts remain unsuppressible. Block still requires signed, live,
eligible process evidence and explicit confirmation, with the existing Combat
submission and durable SOAR audit checks. Opening another view grants no new
host authority. No sensor cadence or cloud permission changed.

## Validation

- **15 new regressions** cover all seven entry paths: dashboard summary, event
  history, module feed, module history, module resources, Resolve detail, and
  Live Alerts rows. They also cover separate sessions, detached bus matching,
  exact-scope undo, empty-feed expiry, cancellation, integrity refusal, analysis
  deduplication/queue feedback, late results after close, and containment refusal.
- Adjacent alert, Resolve, SOAR, snapshot, lifecycle and animation tests:
  **97 passed** on Python 3.12 / PySide6 6.11.1.
- Full Python 3.11.9 / PySide6 6.11.2 suite: **3,658 passed, 19 expected
  environment/platform skips, 0 failures**, including the prior native-crash
  sequence. Scoped Ruff, full source/test/tool compilation, documentation drift
  validation and Git whitespace checks pass.
- A rendered 1240 × 780 detail was visually checked after allowing a synthetic
  alert while its feed remained hidden. Allow status and enabled Undo Allow
  were visible in the same window. Preview data was isolated under `.tmp`;
  no live alert, process, trusted-process policy or model was used.

The first [CI run](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/35044140121)
passed Python 3.10–3.12 and all platform/security checks. Python 3.13 exposed a
sorting assumption in the new Live Alerts test: its opener inserted a duplicate
into a sorted table and then clicked row zero, which could be another alert.
The fixture now finds the existing row by exact event identity, verifies the
opened record, and deliberately gives the neighboring alert a newer timestamp.
No application code changed for this correction. The corrected 15 cases pass
on Python 3.11, and the adjacent 97-case selection passes again on Python 3.12.

This source maintenance update keeps version 1.13.0. Restart the source
application to load the new UI behavior. Publication uses the guarded publisher
and must verify exact public main/branch identity and every README image.
