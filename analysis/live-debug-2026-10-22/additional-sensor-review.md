# Additional sensor admission review

This source review covers six default Windows providers held outside the
14-sensor observation allowlist. No default native provider was launched, no
mapped drive or remote service was created, and no host policy was changed.
The findings are admission limits and source defects, not demonstrated
intrusion, provider hangs or network transfers.

| Provider | Verified source boundary | Remaining admission work |
| --- | --- | --- |
| App Control Decision Evidence | Local Code Integrity queries and private authenticated cursors; corrected health classification and published explicit 500-ms `EvtNext` wait | Whole-query duration and active cancellation remain unproven. The native empty-channel query retired normally, but it did not induce a timeout. |
| Driver Provenance Guard | Local inventory, driver-file hashing and signature checks; evidence correctly remains unbound to the loaded image | Guarantee offline signature retrieval and fixed-local component access. Sequential provider timeouts can exceed the observation harness's 15-second drain. |
| Kernel-Boundary Posture Ledger | Reviewed absolute inbox-tool resolution and retained, bounded ledger reads are applied; timestamp-only differences no longer imply semantic posture drift | Preserve the signed timestamp evidence and existing ledger byte compatibility. Sequential native calls and registry access still need bounded shutdown ownership before active admission. |
| Platform Attestation Guard | Read-only local OS/TPM metadata; default provider does not manufacture a hardware quote | Sequential calls have a nominal 30-second provider window, beyond the current 15-second drain. Add cancellation/retirement proof before expanding admission. |
| Peripheral and DMA Posture Guard | Read-only local PnP/CIM/policy facts; exact observer-denial classification now corrected | Its nominal 20-second call can exceed the current drain. Unknown hardware/device coverage remains unknown. |
| Authentication Extension Integrity Guard | Fixed read-only registry surfaces and retained-descriptor component hashes; exact collection-denial classification now corrected | Drive-letter syntax alone does not prove a fixed local volume. Gate mapped drives and reparse ancestors before filesystem access; provide generation-aware cancellation. Default signature evidence remains unavailable. |

App Control's original wrapper call omitted the timeout and defaulted to an
infinite wait. The published correction supplies 500 ms and distinguishes
normal exhaustion from timeout/collection loss. It does not impose an overall
query deadline or prove cancellation of every native call.
[pywin32 EvtNext contract](https://mhammond.github.io/pywin32/win32evtlog__EvtNext_meth.html).

Driver signature checks do not establish a no-egress guarantee merely because
the inventory command is local. Windows documents an explicit cache-only flag
for preventing code-signature retrieval from the network. No such transfer was
observed in this review.
[Microsoft trust-provider flags](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data).

The Kernel Ledger's original unqualified executable names are replaced with
reviewed absolute inbox-tool resolution and explicit unavailable-tool results.
Its ledger reads now retain ancestor/file custody and enforce file/row byte
limits before parsing, while preserving historical newline compatibility.
The applied changes are included in the 366-pass focused acceptance. They do
not make the complete provider cancelable or eligible for the active matrix.
[Microsoft executable resolution](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw).

Three precise classifier corrections are implemented: App Control denial,
Peripheral observer failure and Authentication collection denial. Their
affected suite passed **251 tests**, including actual inert producer callbacks,
armed EventBus validation and tampering/contradiction controls. Unexpected
errors and genuine detections remain active. Those fixes do not remove the
provider admission holds above.

The providers overlap on DeviceGuard, Secure Boot, BCD, Code Integrity and file
hashing. A future shared read-only posture broker could avoid repeated native
queries by handing off immutable, dated receipts with producer/generation
identity, explicit field completeness, freshness, loss and cancellation
ownership. Sharing a cached value must not create response authority or turn
an unavailable field into a healthy result. This broker remains a proposal.

The wider runtime matrix still holds 72 capabilities for individual active-path
review. Offline self-tests, declaration metadata and read-only labels do not
authorize starting those workers.
