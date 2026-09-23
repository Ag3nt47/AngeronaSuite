# Adversary review — deep review round 1, 2026-09-23

Scope: `AngeronaSuite-deep-review-20260923`, base `7b7b264` plus the explicitly
authorized pending Analysis Lab. Product source was read only. One MEDIUM
configuration-custody finding was verified with source tracing and an entirely
in-memory dependency fixture. No VM, analyzer, sensor, hostile program, network
request, host control change, or product edit was performed.

The user additionally requested emphasis on defenses against adversarial AI.
This pass treated repository text, telemetry, model responses and external
analyzer results as untrusted input; a claimed model verdict was not treated as
execution or response authority.

## D23-R1-01 — Mutable VM configuration breaks custody of the reviewed guest

- **Severity:** MEDIUM
- **Status:** OPEN at discovery
- **Components:** `src/angerona/core/tool_analysis_jobs.py:339-375`, especially
  lines 367-370; `src/angerona/core/analysis_vmware.py:95-103,106-139,179-207`.

### Description and data flow

The host generates a fixed diskless/no-NIC/no-shares VMX profile, writes it to
`runs/<job>/analysis.vmx`, and invokes VMware with that pathname. The surrounding
`ExitStack` retains sealed handles for the pinned appliance components and
`boot.iso`, but never opens a sealed handle to `analysis.vmx` or compares its
bytes again. Directory guards prevent path redirection; they do not deny writes
to an existing file inside the directory.

The local job directory belongs to the normal-user Analysis Lab session. A
concurrent actor with write access can replace the boot-media filename or other
VM settings between the host's generation and VMware's consumption of the
configuration. Sealing the intended `boot.iso` does not prove VMware selected
that image. `_client_job()` checks the signed VMX executable path, process birth,
command-line VMX pathname and absence of children; those checks do not establish
which bytes were read from that VMX pathname.

Consequently the host's report checks can be satisfied by a different guest
configuration at the same expected pathname. An alternate guest sees the job ID
in the predictable pipe/profile identity and can produce the fixed readiness
handshake and a schema-valid report. The report's network/block/share claims are
self-reported guest data, not independent host verification of the VM profile.

### Impact and existing controls

This weakens the claimed binding between an accepted external-analysis result
and the reviewed offline analyzer appliance. It can substitute the guest image
or relax isolation when a local writer races startup. It is **not** a demonstrated
hypervisor escape, privilege escalation, or direct prompt-injection-to-execution
path. Same-user write authority and timing are prerequisites, which limit the
severity. A hostile repository alone was not shown to acquire that write
authority.

Credited controls: the Lab refuses elevated execution; package/artifact hashes
are exact; source names become opaque input names; host inputs are bounded;
the intended boot image is sealed; named-pipe clients are restricted and checked
against the signed VMware process; a Job Object limits VMX memory/processes and
kills it on close after admission; the trusted guest checks devices before
analysis; report schema and job identity are strict; saved results are explicitly
external analysis with no response authority. These controls do not substitute
for retaining the VM configuration's identity and bytes.

### Inert verification

The real `_run()` function was called with a dictionary-backed filesystem,
`BytesIO` artifact handles, a no-op ISO builder and a fake supervisor. No real
files were created. The sealing shim tracked every retained path. At supervisor
entry the fixture asserted that the VMX was not among those paths, changed only
`ide0:0.fileName = "boot.iso"` to `ide0:0.fileName = "alternate.iso"`, and returned
a strict, matching job report. `_run()` accepted it. Observed result:

```text
report_accepted=True
changed_vmx_bytes=True
real_files_or_processes_created=False
```

The fake supervisor does not demonstrate native VMware exploitation; it isolates
the host invariant: no VMX custody or exit-time byte check prevents or detects
the substituted configuration before receipt acceptance.

### Recommendation and acceptance tests

Bind the exact generated VMX bytes, file identity and expected boot-media path
to the job before invoking VMware. Retain a Windows handle denying write/delete
sharing through the relevant lifecycle, using the existing source/boot custody
pattern where VMware permits it. If VMware legitimately rewrites the VMX,
implement and document a verified handoff that proves the selected boot/devices;
do not silently drop the custody requirement to make native acceptance pass.
Validate the fixed configuration again before GO and receipt acceptance, and
keep teardown bound to the same admitted job.

Regress VMX overwrite, replacement, boot-media substitution, changed device
settings, rejected local alias, and attempted substitution immediately before
start. The negative test must prove zero GO/report acceptance. Run a separately
authorized inert native acceptance gate to establish that VMware supports the
chosen configuration-custody mechanism without disturbing existing VMs.

## AI-input and authority review results

- Reviewed the complete five-file Lab core and GUI panel. The Lab has two fixed
  analyzer commands; it does not dispatch source text as a shell command or
  import repository code. Opaque input names and explicit configuration paths
  prevent project filenames/configuration from selecting adapters or commands.
- Guest analyzer output is reduced to file/rule/line/severity metadata. The host
  enforces an exact report schema and matching job/input/catalog identities.
  GUI report rendering is plain text; no response action is wired to Lab results.
  Poisoned prose or embedded repository instructions were not shown to become
  host action authority.
- AI Triage's generation checks, pre-inference model attestation, bounded
  telemetry neutralization and INFO-level verdict publication were inspected.
  No new prompt-to-response authority bypass was confirmed. Neutralization is
  credited as input handling, not a guarantee that a model cannot be misled.
- Counter-Agentic's process-rhythm and inference-port paths were sampled. Its
  heuristic labels do not establish that an adversary uses a particular model.
  Existing cycle27 findings were consulted; no duplicate finding was filed.
- ARIA dispatch registers state-changing agent invocations as WRITE operations
  behind the assistant confirmation mechanism. The Lab adds no bypass of it.

## Prior-control verification and limits

Read `analysis/loop/state.json` (historical cycle34 round3 complete),
`PRIOR_FINDINGS.md`, the September 21 adversary report/closure, the prior Lab
implementation evidence, and relevant cycle27 module findings. Historical loop
reports were preserved.

The two September 21 findings were rechecked in current source:

| Prior finding | Current verification | Status |
|---|---|---|
| R20260921-01 retained disabled callbacks | NDRD/PROV/MEMC return on stop; SPEC carries and revalidates the original generation token before admission | Resolved |
| R20260921-02 stale startup/console revival | Staged starts use `_start_current`; it checks manager generation, shutdown, exact registered instance and current selection; console restart refuses off modules and uses the same manager admission helper | Resolved |

This was a bounded first pass, not an exhaustive audit of all modules, installers,
hypervisor dependencies, or native guest behavior. Existing Lab evidence explicitly
says live VMware acceptance remains pending; this pass does not change that status.
Installer and deeper AI research are assigned separately by the coordinator.

| New severity / prior disposition | Count |
|---|---:|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 1 |
| LOW / INFO | 0 |
| Prior findings verified resolved | 2 |
| Prior findings verified still open in this pass | 0 |
