# September 23 maintenance upgrade

This v1.13.0 maintenance pass repairs the YARA-to-response path behind a reported
Shark failure, reduces duplicate collection and scanning, and adds practical
engine, retention, AI-integrity and recovery tools. The shared catalog remains
84 capabilities; these changes strengthen existing modules and core workflows.

## Detection and automatic response

The reported Shark run showed no compatible analytic catches or response
actions. Review found two separate breaks: actual YARA alerts lacked the typed
positive evidence and content identity needed by response, and the production
Shark report never supplied its native-producer verifier. The upgrade connects
both paths. A signed event alone cannot claim native detection: the report also
checks the currently registered producer, engine graph, lifecycle and its actual
scan receipt.

Native Windows inert plain-file and ZIP tests exercised the real YARA-X engine
and live Combat worker through automatic quarantine, signed verified outcomes
and Undo, without Ollama or manual action dispatch. Changed file content is
rejected before mutation. The inert BYOVD fixture now has a real scan signature;
it does not load a vulnerable driver. These tests establish the tested file
response path, not complete coverage of all 21 steps from the original run.

Adversarial review also found that archive errors discarded known positives and
that Python allocated ZIP member metadata before applying its limit. Bounded
central-directory preflight now precedes that allocation. Verified positives
survive incomplete archive inspection, with the coverage gap retained and no
clean scan-cache entry. Windows held-handle change tokens fix inconsistent
path/descriptor ctime comparisons without accepting restored-mtime changes.

## Performance and operation

Shared rich process snapshots preserve loss and PID birth identity while
avoiding repeated process walks. A three-consumer component benchmark changed
from 314.210 to 99.543 ms, a 68.32% reduction. A separate 48-file / 6.72 MB YARA
fixture changed from median 2556.949 to 66.532 ms on unchanged cached scans.
The latter ran alongside offline tests. These measurements do not establish
whole-PC speedup, sustained idle CPU or multi-day memory stability.

Runtime alert copies now use a bounded background writer, 4 MiB rotation and
fair bounded cleanup. Defaults are 30 days and a 256 MiB target, adjustable in
System settings, initial setup and the separate engine console. Pins and
inaccessible files can keep usage above the target; cleanup status exposes
that condition. Signed evidence, response journals, recovery data, cases and
exports are outside this cleaner's scope.

The optional detached engine runs independently of its console. It supplies
authenticated, bounded local operations for module state, self-tests, restart,
Chill mode, retention and explicit shutdown. Native per-user startup tooling
uses Task Scheduler, launchd or systemd. This is ordinary-user persistence;
privileged Windows service deployment requires separately provisioned release
authority and native acceptance. The complete workbench remains available.

Process-tree resource sampling includes CPU, memory, I/O, threads and native
handles where available. Opt-in runtime metrics add actual queue counters and
GUI timing; headless GUI latency remains explicitly not applicable. Long soak
profiles require fresh metrics bound to the measured process lifetime.

## AI integrity, recovery and rule quality

Explicit AI-file enrollment binds approved instruction, memory and tool files
to exact digests and selected integrated tools. Assistant/broker execution and
Counter-Agentic monitoring consume that policy. Same-session baseline rollback
and Windows short-name alias bypasses are rejected. Windows holds approved
bytes through mapped actions; POSIX mapped mutations remain withheld without
an immutable consumer adapter. External agents and their socket traffic are
not automatically controlled by this feature.

The recovery CLI performs an actual encrypted backup and restores into a new
private directory, checking hashes and authenticated drill evidence. The native
fixture covered three files / 1107 bytes, second-process protected-key access
and tamper rejection. It is a local recovery drill, not an independent backup
failure domain. A separate labelled-replay CLI compares verified detection
packages and reports true/false positives and negatives with optional thresholds.
Its fixtures are event data; it executes no attacks.

## Evidence and remaining work

The final serial regression run passed **4,303 tests with 20 skips and no
failures**. Independent selfcheck passed all 26 phases. Native acceptance and
component measurements retain their individual scopes in the linked records.

- [Usage and settings](usage.md)
- [Validation results and limits](validation.md)
- [Independent bug-hunter checks](bug-hunt.md)
- [Adversarial findings](adversary-review.md)
- [Comparison with upstream projects and prioritized backlog](comparison.md)
- [YARA cache measurement](yara-cache-benchmark.json)

Publisher signing and Apple notarization identities are not configured. Trusted
installer and privileged-service acceptance, elevated Ollama process acceptance,
and representative 24-hour/7-day soaks remain open. The prior native QEMU Lab
results and Mac/Linux source-launcher CI remain separate dated evidence in the
[continuation](../continuation-20260923/README.md) and
[deep review](../deep-review-20260923/README.md).

Proposed follow-ups include a sensor-demand collection plan, broader native
containment acceptance, independent backup destinations, immutable POSIX AI
consumer adapters and native egress enforcement for enrolled AI applications.
They are backlog, not shipped capabilities.
