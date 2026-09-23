# Adversary review — deep review round 2, 2026-09-23

Scope: the September 23 worktree's new Ollama lifecycle/transport integration,
semantic threat classification and remediated Analysis Lab VMX custody. This was
a bounded defensive review. Product source was read only; the only executable
addition by this reviewer is the inert regression suite
`tests/test_ollama_endpoint_binding.py`. No daemon, sensor, guest, hostile program,
network listener or native analysis job was started. Root and the patch agent own
the fixes and their broader acceptance gates.

Historical `analysis/loop/state.json` remains cycle34/round3 COMPLETE; those
completed reports are not this new review's state and were preserved. The prior
September 23 round1 report was consulted to avoid duplicate findings.

## D23-R2-01 — Semantic-only command text incorrectly triggers active-threat work

- **Severity:** LOW
- **Status:** Fixed in working-tree producers/classifier during review; broader
  regression evidence belongs to the patch agent's round2 report.
- **Components:** `src/angerona/modules/lsass_guard.py:245-274`,
  `src/angerona/modules/shadowcopy_guard.py:211-249`,
  `src/angerona/core/threat.py:event_disposition`,
  `src/angerona/core/chill_mode.py:111`,
  `src/angerona/modules/ai_triage.py:428-443`.

### Verified behavior before remediation

Both sensors already distinguish an exact executable/argument match from a
semantic keyword-only match when constructing response authority. The latter
does not receive a process response contract. Nevertheless, both branches emitted
CRITICAL events with `active_attack=True`. The shared threat classifier treated
them as active, Chill's active-threat observer escalated, and the AI Triage
active-event gate admitted them for subsequent inference checks.

A completely mocked one-iteration process scan reproduced this with these
inert argument arrays; the commands were never executed:

```text
name=python.exe, exe=C:\Python\python.exe
argv=["python.exe", "-c", "print('mimikatz lsass.dmp')"]

name=cmd.exe, exe=C:\Windows\System32\cmd.exe
argv=["cmd.exe", "/c", "echo vssadmin delete shadows"]
```

Each fixture used PID 4251, birth 1234.6, a fake `psutil.process_iter`, a local
EventBus and `module.sleep = lambda _: module.stop()` to stop after one scan.
For ShadowCopy the parent PID query was also stubbed. Selecting the emitted
`detector_policy == "semantic-indicator-alert-only"` event and evaluating
`event_disposition`, `is_active_threat` and `ChillPolicy.observe_active` produced:

```text
response_contract_present=False
severity=CRITICAL
disposition=active
is_active_threat=True
chill_action=escalate
```

### Impact, limits and recommendation

Attacker-controlled command text can manufacture active alerts and unnecessary
heavyweight work without performing the reported credential/recovery operation.
Repeated process generations can renew that stimulus. Existing per-generation
alert deduplication, AI queue limits/cooldowns and model readiness checks limit
the cost; no unauthorized containment or direct model-to-host execution was
demonstrated. This is a low-severity induced-work and alert-integrity issue.

Preserve the evidence as an observation unless exact execution scope or
independent corroboration supports an active threat. Set explicit observation
disposition, no active-attack assertion and `response_authorized=False` for the
semantic-only producer branches. Keep genuine exact-command detections active
even when missing process birth prevents a response contract. Do not globally
equate absence of a response contract with absence of a real threat. Historical
events need a narrowly scoped classifier correction that preserves independently
corroborated and response-bearing events.

The patched source now branches on `bool(scope)` / `exact_command`, not on the
presence of a response contract, and emits the explicit observation fields.
The patch agent owns positive, negative and historical-event regressions.

## D23-R2-02 — Ollama attestation was not bound to the HTTP endpoint address

- **Severity:** MEDIUM
- **Status:** Fixed in working tree; all 13 new inert regression cases passed.
- **Components:** `src/angerona/core/ollama_lifecycle.py:318-364`,
  `src/angerona/core/url_policy.py:231-285`.

### Verified behavior before remediation

`_ollama_listener_pids(port)` selected any listener on either `127.0.0.1` or
`::1` at the requested port, then discarded wildcard listeners. Attestation
checked that selected process's image and birth, but did not require that
process to own the address to which the HTTP request would connect.

The inert socket/process fixture contained exactly:

```text
trusted Ollama PID 101: LISTEN [::1]:11434
other process PID 202: LISTEN 0.0.0.0:11434
requested endpoint:  http://127.0.0.1:11434
observed attested PID: 101
```

`_ollama_tcp_listeners` returned synthetic socket rows. Process identity methods
and the executable trust check were stubbed with a fixed existing image and
stable birth; there were no real sockets or child processes. The real attestation
function returned PID 101 even though the requested IPv4 endpoint belonged to
PID 202 in that fixture. Explicit IPv6 loopback and IPv4 wildcard sockets can
coexist; inspecting only the shared port does not establish endpoint ownership.

Additionally, `safe_urlopen` attested the hostname before separately pinning
that hostname for HTTP. A changed resolution could therefore select a different
loopback address for attestation and transport. The new transport regression
returns IPv4 on the first mocked lookup and IPv6 on any second lookup, then
asserts that attestation and HTTP use the same numeric address with one lookup.

### Impact, controls and remediation

An unrelated local endpoint could receive local AI requests or supply forged
service/model responses while ownership was attributed to a trusted process on
the other family. Existing signed executable, stable process identity, bounded
HTTP, model integrity and response-authority controls remain material
mitigations. This finding does not prove autonomous execution from model text,
remote access to the loopback service or a privilege escalation.

The root fix passes the pinned literal address to listener admission, matches
that address exactly, and fails closed on wildcard listeners affecting it.
IPv6 wildcard listeners are conservatively ambiguous because the socket table
does not expose `IPV6_V6ONLY`. HTTP now pins before attestation and uses that same
literal for the request. Unrelated explicit listeners on the opposite family or
another port do not block a trusted exact endpoint.

### Regression evidence

`tests/test_ollama_endpoint_binding.py` contains 13 cases covering:

- IPv4/IPv6 wrong-family-only listeners;
- opposite-family trusted listeners with an applicable wildcard, matching-family
  wildcard ambiguity, and IPv6 wildcard ambiguity for IPv4;
- trusted exact endpoints with unrelated explicit listeners;
- identical attestation/transport pinning for both URL strings and Request
  objects, under both the dedicated Ollama and generic local policies;
- preservation of the Request method, body and content type.

Validation used the existing `AngeronaSuite/venv/Scripts/python.exe` with
`PYTHONPATH` set to this worktree's `src` and the repository's isolated test
runtime. Result: **13 passed in 1.90 seconds**. All network opening, resolver,
socket inventory and process inspection behavior in these cases is mocked.

## Prior-finding closure and review limits

**D23-R1-01 (VMX configuration custody): resolved in source.** Re-read
`analysis_vmware.sealed_configuration` and its caller lifetimes: the fixed VMX
bytes, file identity and link count are checked while a sealed handle is held;
the job runner retains it through supervision/report acceptance, and the
supervisor revalidates before start, GO and report return and retains its seal
through teardown. Native VMware acceptance remains a separate gate and was not
claimed or performed here. The parent's latest status identifies the disabled
VMware Authorization Service as that gate's current blocker.

The bounded startup review also checked fixed daemon launch arguments, service
versus model readiness, cancellation checks, startup-attempt limits, and plain
text GUI status rendering. No additional verified startup authorization or
hostile-tool-text execution bypass was found in this pass. This is not a claim
of exhaustive startup race coverage. Installer changes and the VMware service
helper are assigned to a later review once their implementations are stable.

| New severity / prior disposition | Count |
|---|---:|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 1 |
| LOW | 1 |
| INFO | 0 |
| Prior findings verified resolved in this pass | 1 |
| Prior findings verified still open in this pass | 0 |
