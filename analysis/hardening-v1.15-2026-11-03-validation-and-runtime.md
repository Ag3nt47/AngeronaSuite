# Runtime and validation review

3 November 2026 · Angerona 1.15.0 source preview

## Retained runtime evidence

A one-minute review in Full mode retained 2,284 event records, including
historical records already in the retained window. The capture recorded one
explicit continuity gap. Infection status remains unverified.
[Runtime review guide](../docs/live-debug-harness.md)

One GUI heartbeat was delayed by about 43.9 seconds. The diagnostic sample
showed only the Qt event loop, and five later window-message checks answered.
The black dashboard image followed a diagnostic Windows restore outside Qt’s
supported tray or orb restore path. A separate fresh diagnostic launch later
failed with Windows callback exception `0xC000041D`. The causes of the black
dashboard, the callback failure and the earlier native shutdown fault remain
open.

The latest dashboard STOP completed with native Core exit code 0 through the
normal managed path. The fresh managed GUI report recorded retirement and zero
pending UI workers. The stop completed without force.

## Scan coverage and report storage

The report-count hold describes storage admission. All eight then-default report
slots were occupied, using about 0.7 MiB of a 64 MiB allowance. Native checks
finished, and the toolkit remained held before launch. The result showed an
empty findings list and incomplete coverage.
The next observed source build used Unlimited and admitted a ninth job with all
eight previous report directories intact. The toolkit finished in about 47 minutes
without timing out. Its retained receipt verified seven retired worker generations
and the hashes of the recorded outputs. It reported one historical browser
record for published advertising infrastructure and two reference matches. The
browser, hash, host, trace and Windows execution readers retained coverage gaps.
The historical browser record did not establish spyware execution. A separate
read-only native Chromium reader found the same profile record in a bounded check.

The dashboard returned the scan controls to idle. Two native observations found
no after-action window. The retained report remained accessible on disk. A follow-up
revision adds a visible report-opening control and separates terminal delivery
from replaceable progress updates.
[Toolkit and scan coverage guide](../docs/zero-breach-toolkit.md)

## Independent scanner and device checks

The native priority scan adds bounded Chromium HSTS checks, local hosts-file
overrides, selected-file signature review, and Windows launch configuration.
These readers can run without Zero-Breach. Their findings are recorded
separately so two readers can corroborate the same evidence without creating
two incidents. HSTS records describe past browser state. A hosts-file entry can
be a deliberate local block. IFEO and Silent Process Exit values describe how
Windows is configured to launch a process.
[Microsoft launch configuration](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/registry-entries-for-silent-process-exit/)

One read-only Windows verification checked 146 launch configuration entries,
reported six skipped entries and found no advisory in those checked. The
hosts-file reader finished with no match. Windows returned a bounded accessory
sample with no mixed-function combinations, while Kernel DMA Protection state
remained unknown. Device class and container membership describe functions
visible to the host. They do not inspect embedded firmware or establish physical
authenticity.
[Hardware additions detection](https://attack.mitre.org/techniques/T1200/) ·
[Microsoft Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)

Attached Windows storage can receive a bounded advisory scan after the exact
volume and PIN approval are established. Scan Center does not issue a response
proof, so this path cannot quarantine a file or isolate a device. Live bot and
agent behavior observations use process-linked source evidence when available.
Timing alone stays advisory, and the report does not infer an AI actor from
ordinary installed AI tools or network connections.
[MITRE DNS command and control](https://attack.mitre.org/techniques/T1071/004/) ·
[OWASP agentic security risks](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)

Native coverage still differs from the toolkit for browser databases, broad
hashing, Windows execution history, non-Windows persistence traces and
operator-acquired mobile data. Mobile evidence collection needs its own
explicit scope, and passive network inspection needs an observable traffic
path.
[Zero-Breach integration guide](../docs/zero-breach-toolkit.md) ·
[Mobile Verification Toolkit](https://docs.mvt.re/en/latest/)

## Notifications and setup

The notification row previews its own description on hover. Clicking the row
or its review button opens the original controls for that exact request. USB
prompts use their own approval identifiers. Creating the first PIN uses the
protected store’s create-only transaction and preserves existing credentials,
lockouts and cancellations. Full Setup exposes automatic scan scheduling,
scope and report retention.

## Public demonstration and release scope

The 70-second demonstration contains 140 frames. Review covered 14 screenshots
individually and the final GIF. The Qt views display synthetic example data.
[Application demonstration](../assets/demo/angerona-demo.gif)

The focused Windows run passed 403 tests across scanner storage, notifications,
source startup readiness, release authorization and dashboard coverage. Its
source fence matched and native test processes retired normally. All four
observed role counters advanced in authenticated heartbeat records.

The prior public CI run had seven failures in each of its four Python jobs.
They covered Red Team ownership setup, Settings window modality and YARA
containment. The local follow-up addresses those areas. Hosted acceptance needs
a run for the published revision.
[Prior GitHub CI run](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/41445357103)

The 14,790-case local Windows run reached its two-hour deadline after 11,339
terminal case results, including 13 failures. The owned diagnostic Job retired
and the source fence matched. Corrections were verified separately where noted.
A property-test generation delay did not recur in two unchanged isolated
retests. One earlier private combined test process failed with a Windows native
access violation and has no established cause.

Hosted checks for the final revision, signed Windows release acceptance,
installed Windows UAC behavior and independent response authority remain pending.
[Release notes](../docs/releases/v1.15.0.md)
