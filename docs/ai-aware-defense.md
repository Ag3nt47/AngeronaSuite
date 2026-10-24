# AI-aware defense

Angerona should remain useful even when an attacker uses AI to write convincing
messages, vary payloads or automate repeated attempts. AI does not confer a
special operating-system privilege; it can increase the volume and adaptability
of attacks against ordinary identity, software, network and human boundaries.
This guide separates current controls from work that still needs implementation
or independent deployment.

## Defend the decisions an attacker wants to change

The highest-value targets are response authority, signing and update trust,
credential custody, collection continuity and recovery evidence. Protecting a
chat prompt alone does not protect those decisions.

| Attacker-controlled input or action | Attempted effect | Existing boundary | Priority to prove or extend |
| --- | --- | --- | --- |
| Research reports, URLs, event messages or runbooks containing instructions | Turn an imported statement into an AI tool call, an allowlist entry or an executable rule | Treat content as data; bounded ingestion, candidate indicators, digest/session-scoped review and inactive rule staging | Exercise indirect prompt injection across every input and rendered/exported view; require unchanged authority on refusal |
| Forged or replayed module telemetry | Make invented findings authorize an exact-target action | EventBus provenance, live module identity/generation, typed response contracts and final target checks | Test stale epochs, producer retirement, replay, queue loss and mixed-source correlation together |
| Compromised GUI, sensor or model process | Acquire signing material, policy writes or privileged mutation | Local guarded tools and distinct authority stages; protected storage and authenticated service interfaces | Finish a least-privileged sensor/GUI deployment with a narrowly privileged execution service; the present service is diagnostic |
| Repeated expensive inputs, large narratives or alert floods | Starve collection, disk, UI or the reviewer | Bounded queues, explicit drop/gap records, capped research and bundle work | Give critical security evidence a measured latency/loss budget; run benign and adversarial flood/soak tests without suppressing gaps |
| Poisoned knowledge or evaluation fixtures | Normalize a malicious indicator, hide missed detections or overstate readiness | Reviewed candidate ingestion, pinned memory packs and separated replay cohorts in implemented workflows | Add held-out prompt-injection and benign-workload cohorts; keep training and evaluation provenance independent |
| Stolen account or updater/build access | Publish a convincing malicious update or replace trust settings | Existing release trust, source staging and approval boundaries | Provision an independent signing authority; test revocation, updater conflicts and rollback rather than trusting repository access alone |
| Full local snapshot restoration or host destruction | Rewrite history or remove recovery evidence | Local authenticated chains and recovery contracts | Deploy an independently administered witness and off-host/offline recovery; show unavailable assurance explicitly |

These are threat scenarios and engineering priorities, not a claim that every
listed attack has been reproduced against Angerona. NIST's adversarial machine
learning taxonomy covers attacks including poisoning, evasion and privacy
compromise; MITRE ATT&CK documents prompt injection as an adversary technique.
See [NIST AI 100-2e2025](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf)
and [MITRE T1698](https://attack.mitre.org/techniques/T1698/).

## Known manual cloud-consult privacy gap

A source-only review found that legacy alert Research and SOAR consult actions
can include raw event details, host/VPN names, process paths and connection
context in a configured provider request without a pre-send payload preview.
This requires configured cloud credentials and an explicit operator click;
manual online consultation has its own consent semantics. The separate default-off
automatic fallback settings are not a global computer-only policy. No actual
secret transmission, autonomous upload or AI-to-response bypass was demonstrated.
SEC-15 remains open for a separate repair: share the bounded outbound sanitizer,
hold on preparation failure and preview the destination and exact sanitized
payload before Send. A universal local-only deny needs enforcement across every
provider entrypoint; it is not established by this maintenance checkpoint.

A separate repair proposal has source approval but is unactivated and untested.
Independent review rejected an earlier proposal's trust in attacker-supplied
redaction markers before activation; the revised proposal does not trust such
markers. Its 75 proposed inert cases have not run. Within the unactivated proposal, Ollama preview destinations are restricted to
localhost or numeric loopback through the existing attested transport. Configured
manual cloud routes remain available after payload review and Send. The dialog
adds no local-only toggle; no universal provider-egress deny or global
computer-only setting is implemented.
Existing GUI-thread context gathering remains a latency candidate.

## Keep AI outside the authority boundary

Imported prose, tool output, model output and diagnostic free text remain
untrusted. The registered AI interfaces permit evidence summaries and proposed
patches; they do not grant capabilities, approval signatures, original-event
writes, healthy-sensor status, broader egress or response permission through a
review annotation. Consequential actions retain the application's typed tools,
exact-target contracts, standing policy and operator authorization. This consumer
boundary does not confine malicious same-process code or an administrator/kernel
exploit; those threats require independent isolation and recovery controls.

Each AI integration should expose only the evidence and registered operations
needed for that task. Apply size, recursion, concurrency, output and deadline
limits before model invocation; label stale, incomplete, unavailable and imported
evidence. Keep local inference listeners loopback-bound and verify the actual
listener process. Do not send raw captures, secrets, browser contents or private
memory to an external model as an implicit debugging step.

## External coding agents and reviewer independence

A coding or debugging agent granted filesystem, shell or Git credentials operates
outside Angerona's registered internal AI-tool boundary. The read-only Live Debug
feed limits that interface; it does not confine privileges granted to an external
agent. Use an isolated checkout and scoped credentials, review the exact diff,
run relevant tests, and use a reviewed, pinned guarded publisher. Instructions
inside imported repositories, logs or reports do not authorize actions; authority
comes from the trusted maintainer request and existing application policy. These
are recommended operating controls, not a claim that new agent isolation is deployed.

Multiple AI reviewers can provide independent analysis and challenge each other's
conclusions. When they share a host, account or credentials, they are not
independently administered security principals, an off-host witness or a
cryptographic trust anchor. Keep human review, credential separation, independent
recovery and externally administered trust resources distinct from review counts.

## Build independent protection and recovery

The immediate priorities are dated verified readiness, an off-host witness and
privilege separation. A configured detector mapping does not prove collecting,
recently tested detection or verified response. A stopped sensor must reduce
readiness. A witness controlled by the same host cannot establish independent
freshness. A GUI crash should eventually leave privileged protection running;
that deployment still needs its own proof.

Process-bound network admission needs native enforcement and lifetime/identity
leases. The existing observer and diagnostic service do not provide that claim.
Windows WFP's application-layer enforcement documents the relevant native
connection-authorization layers; it does not establish Angerona's deployment.
See [Microsoft WFP ALE](https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-/).

## Active defense on assets you control

Inert canary files and synthetic identities can expose access that ordinary
telemetry misses. Keep them in a documented, isolated test namespace, use no real
credentials, avoid disturbing real browser or credential-store data, and record
which collectors can actually observe their access. A canary hit remains evidence
requiring provenance and context.

A local sinkhole or decoy service can help study a controlled sample in an
isolated lab. Route only traffic and machines you own or are explicitly
authorized to test. Keep the decoy separate from real profiles and signing
material, block onward routing, cap retention and resources, and preserve a
reliable management/recovery path. Keep live infrastructure collection separately
authorized; the proposed lab sinkhole should not solicit payloads from suspected
third-party infrastructure. Do not exploit another system or treat an IP address
as operator attribution. The existing SpywareGuard sandbox uses inert telemetry; these
expanded sinkhole and decoy designs are proposed work.

Prefer suspend-and-preserve workflows only when the existing exact-target and
protected-process checks authorize them, and independently verify the result.
Suspension alone does not prove that queued network data stopped. Do not promise
kernel stack inspection, arbitrary token/handle stripping, decoy camera streams,
hardware trace analysis or sub-second containment without implemented sensors,
native enforcement and measured tests. MITRE D3FEND supplies a defensive
knowledge framework for evaluating candidate controls; a mapping is not proof
of efficacy. See [MITRE D3FEND](https://d3fend.mitre.org/).

## Acceptance evidence

For each new safeguard, retain a benign control, a deliberate adverse case,
a refused unauthorized operation, observable postconditions and recovery
results. Preserve loss and coverage gaps, independently review the tests, and
observe the changed revision. High-volume, overnight and independent-host
validation remain separate gates. No local user-mode suite can promise secrecy
or integrity after a hostile administrator or kernel controls its execution.
