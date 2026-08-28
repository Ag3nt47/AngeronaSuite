# Cycle 25 / Round 1 — Upstream defensive-project comparison

Date: 2026-08-28
Mode: primary-source comparison; no parity scoring

## Method

This comparison used the projects' own documentation or repositories to find
useful defensive patterns. It is not a benchmark, endorsement, compatibility
claim, or assertion that Angerona replaces a supported fleet product.

| Upstream pattern | What the primary source establishes | Angerona v1.12 disposition |
| --- | --- | --- |
| Velociraptor client monitoring | Persistent endpoint event queries start with the client; offline results can remain in a local buffer and forward after reconnect. | **Adapted locally, not fleet parity.** SIEM/Remote exporters use durable local outboxes, revision cursors, and drain-stage-drain ordering. Angerona does not ship Velociraptor's server-synchronized event tables, label groups, hunts, or datastore. |
| Wazuh Active Response | Response scripts can be trigger-driven; stateless actions are one-time, while stateful actions stop or revert after a period. Wazuh warns that poorly implemented response can increase endpoint risk. | **Narrower by design.** Angerona favors typed exact-target actions, immutable approval data, verified postconditions, receipts, compensation, and exact Undo. It does not expose a general automatic response-script surface or claim Wazuh agent/server orchestration. |
| Fleet GitOps policies | Policies are query-backed, platform-scoped records with descriptions/resolutions and optional controlled automation fields. | **Contract idea adapted to one host.** v12 capability contracts expose platform, mode, permissions, dependencies, settings, health, loss, and resource budgets. Host adaptation profiles are closed and locally reviewed; this is not Fleet GitOps, device enrollment, or fleet policy distribution. |
| osquery query packs | Packs group queries and can apply platform, version, shard, and discovery selectors; scheduled and snapshot queries have distinct behavior. | **Selector discipline, not arbitrary packs.** Angerona inventory and discovery validate declared platform/lifecycle contracts. Its osquery integration remains fixed, read-only, bounded templates—not distributed arbitrary SQL or a pack marketplace. |
| Elastic detection-rules | The repository treats detection content as code with parsing, validation, packaging, testing, and release tooling. | **Admission lesson applied.** Angerona's deliberately limited Sigma subset validates bounded YAML and atomically admits or refuses a batch with a receipt. It is not full Sigma compatibility, Elastic's Detection Engine, or Elastic's rule release pipeline. |
| Velociraptor Artifact Exchange | The exchange explicitly warns that community content may be unsupported, untested, unstable, or download external binaries and should be reviewed before deployment. | **No bulk exchange import.** Angerona's external Python modules remain manifest/signature or explicit development-trust gated; v1.12 does not add an auto-download content marketplace or executable community-artifact path. |

## Standards comparison

- MITRE's version history identifies ATT&CK **19.2** as the current release on
  2026-08-28. Angerona pins a curated endpoint catalog across the 15 current
  Enterprise tactics; it does not claim complete ATT&CK coverage.
- Navigator exports declare ATT&CK 19.2, Navigator 5.3.2, and layer format 4.5.
  The layer format supports exact version metadata and technique annotations;
  Angerona emits only its curated, valid technique rows.
- The OCSF 1.8 source schema defines typed observable/evidence objects.
  Angerona emits resolving typed observable paths under a constrained-preview
  Detection Finding mapping. Its local shape validator is not the upstream OCSF
  schema compiler.
- The Sigma specification is broader than Angerona's evaluator. Unsupported
  logsource, correlation, wildcard, modifier, or condition semantics fail closed
  with bounded reasons; a mixed batch admits nothing.

## Primary sources

- Velociraptor client monitoring:
  https://docs.velociraptor.app/docs/clients/monitoring/
- Wazuh Active Response:
  https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html
- Fleet GitOps YAML:
  https://fleetdm.com/docs/configuration/yaml-files
- osquery configuration and packs:
  https://osquery.readthedocs.io/en/5.12.1/deployment/configuration/
- Elastic detection-rules:
  https://github.com/elastic/detection-rules
- Velociraptor Artifact Exchange:
  https://docs.velociraptor.app/docs/artifacts/exchange_reference/
- ATT&CK version history and Enterprise tactics:
  https://attack.mitre.org/resources/versions/
  https://attack.mitre.org/tactics/enterprise/
- Navigator layer 4.5 format:
  https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md
- OCSF 1.8 observable and evidence objects:
  https://raw.githubusercontent.com/ocsf/ocsf-schema/1.8.0/objects/observable.json
  https://raw.githubusercontent.com/ocsf/ocsf-schema/1.8.0/objects/evidences.json
- Sigma rule specification:
  https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html

The product changes derived from these sources are engineering inferences and
remain bounded by Angerona's own code, tests, and deployment model.
