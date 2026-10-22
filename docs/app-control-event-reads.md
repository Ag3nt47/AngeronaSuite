# App Control event reads

The Code Integrity adapter calls `EvtNext(query, count, 500, 0)`. The 500 ms
timeout limits the native wait for each read, and the reserved flags argument
is zero. Microsoft documents these arguments in
[EvtNext](https://learn.microsoft.com/en-us/windows/win32/api/winevt/nf-winevt-evtnext).

`ERROR_TIMEOUT` (1460) propagates into the sensor's existing collection-gap
handling. It does not become a successful empty channel, a zero watermark, or
an empty record anchor. `ERROR_NO_MORE_ITEMS` (259) remains normal query
exhaustion and returns an empty list. Other errors, including access denial
and invalid handles, continue to propagate. The binding can also return an
empty result directly when a query is exhausted.

This change is limited to the Code Integrity adapter's native read arguments.
Existing queries, event IDs, ordering, rendering, batch limits, handle cleanup,
authenticated cursor state, policy behavior, and response authority retain
their existing behavior. The timeout does not bound the complete query, poll,
rendering, disk writes, scheduling, or shutdown.

`tests/test_app_control_next_timeout.py` has 15 deterministic cases covering
the exact native arguments, returned-handle identity and order, exhaustion,
timeout and other error propagation, watermark/anchor failure, batch limits,
and query/event-handle cleanup. These tests use an inert native API fixture.
