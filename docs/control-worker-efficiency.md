# Control-worker and release-parser efficiency

`EngineControl.close()` wakes an idle control worker with a private identity-only
queue marker. Repeated close calls do not add duplicate markers. A full queue is
never blocked or evicted to make room. The existing 0.5-second poll and 2-second
join limits remain unchanged.

Ready, admission and close share the control lock. A close that wins before work
starts prevents execution and preserves the accepted receipt as queued on the
closed engine. An operation already running completes with its actual result.
The worker is joined outside the receipt lock so that completion can finish.
Repeated ready calls retain one worker, and ready after shutdown cannot restart
it or report a ready engine.

The release syntax check passes its 13 PowerShell sources as JSON stdin to one
trusted PowerShell parser child, reducing that check from 13 process starts to
one. Each source is parsed independently with `Parser.ParseInput`; source text is
never interpolated into commands or executed. Indexed results retain all parse
errors. Missing, duplicate, malformed or exit-code-inconsistent results fail the
check, including single-source batches.

Focused acceptance covers idle wakeup, full queues, in-flight completion,
unstarted receipts, admission/close and ready/close races, parser batching,
indexed errors and inert native parser input. Validation uses a private profile
and temporary tree with imports asserted against the candidate checkout; native
child PID, creation time and retirement evidence are retained outside the tree.
The public base lacks the 1.14 `approval_identity` module, and its control worker
does not call that API. The shutdown fixture therefore has no artificial identity
mock; it uses the existing inert manager and exercises the real worker boundary.
The structural reductions do not establish an overall suite speedup.
