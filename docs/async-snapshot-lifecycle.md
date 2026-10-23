# Async snapshot callback lifecycle

`AsyncSnapshot.request()` calls `prepare` and the optional `updating` status
callback synchronously on the Qt thread. Either callback can close the reader,
delete its owner, or pause a hidden view. The request therefore checks the
closed/paused state again immediately after each callback boundary.

If `prepare` changes that state, the request admits no worker or timer work.
If the status callback changes it after a reader has started, the existing
worker remains owned, but the request does not restart or access its timer.
Deleting a Qt owner cannot leave this path writing to the disposed native
timer.

Closing remains non-blocking and permanent. Pausing keeps the existing bounded
reader available for reuse, invalidates its generation, and stops polling;
an in-flight read may finish, and its stale result cannot repaint the view
after resume. The one-request, one-result and coalesced-follow-up limits, worker
reuse, error handling and 40–250 ms polling intervals are unchanged.

Regression tests exercise close, native owner deletion and pause from both
callback boundaries. They retain every real test-owned thread separately from
the reader reference, observe native timer writes, release blocked readers and
join them during cleanup. Normal delivery and single-worker reuse remain
explicit controls. These checks concern owned inert readers and Qt lifecycle;
they do not establish a cause for unrelated native crashes.
