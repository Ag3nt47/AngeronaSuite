# Analysis Lab: immutable-profile QEMU backend review

The VMware Workstation backend must retain its existing configuration seal.
Workstation needs a writable VMX file, while an ordinary user SID cannot grant
that write access to VMware alone. The implemented separate QEMU backend
supplies its complete device profile in fixed process arguments. It does
not convert the previously failed VMware native check into a pass.

## Runtime provenance

[QEMU's official download page](https://www.qemu.org/download/) names Stefan Weil
and MSYS2 as Windows binary distributors. On 2026-09-23, Weil lists QEMU 11.1.0
in `qemu-w64-setup-20260811.exe`; upstream also lists the newer source release
11.1.1. The distributor explicitly states that newer installers use an expired
signing certificate. This is a reviewed hash-pinned artifact acquisition path,
not a claim that its Authenticode signature currently validates.

The [published SHA-512](https://qemu.weilnetz.de/w64/qemu-w64-setup-20260811.sha512)
for the exact [installer](https://qemu.weilnetz.de/w64/qemu-w64-setup-20260811.exe)
is:

```text
5bcf9eed634e8575a37b74f445af41a2fe4106da512d0c30c368301d4c105037fdfab40a5287367a28a957624cddebbc8c07e16c88ab6634f554cdf3d16bf543
```

The executable installer is treated only as an archive. The extraction chain
uses the official 7-Zip 26.03 GitHub release assets linked from
[7-zip.org](https://www.7-zip.org/download.html). Both downloaded extractor
artifacts are checked against the SHA-256 values returned by that official
release before execution:

| Artifact | SHA-256 |
| --- | --- |
| `7zr.exe` | `ad4c82fadcbdf93c03b4fc440f300509c7d60c5c2f4d183e35d9d70d6957037d` |
| `7z2603-x64.exe` | `0859c524b8a63551848f0c246abddcb1d0b7b656b0fbfe879f8d85e61a9e6edd` |

The standalone extractor unpacks `7z.exe` and `7z.dll` from the verified 7-Zip
archive. Those then inspect and unpack the verified QEMU archive. Neither
installer is executed. Archive names and expansion bounds are checked before
extraction. The resulting runtime manifest records individual SHA-256 values,
sizes, package-relative source paths and recursive normal/delay PE imports.

Acquisition completed with the exact installer SHA-512 above. Four bounded
HTTPS range requests reused the initial partial download; each required HTTP
206, the exact content range and the same strong ETag. The combined file was
206,615,928 bytes. Extraction inspected 3,389 entries with 1,256,078,336 declared
expanded bytes. No installer or QEMU executable was run.

The static minimal runtime contains **109 files / 127,443,388 bytes**: the x86-64
console executable, 104 recursively imported DLLs, two firmware files and both
license files. GTK/GDK/SDL libraries are direct imports of this distributor's
executable, so they cannot be removed merely because the selected profile is
headless. No nested QEMU module DLLs were present; nested DLLs in the original
archive belonged only to the excluded NSIS installer plugins. Subsequent
native module inventories contained only protected runtime and Windows
System32/WinSxS files; see [native acceptance](native-lab.md).

| Reviewed runtime input | SHA-256 |
| --- | --- |
| `qemu-system-x86_64.exe` | `47d57a6072e0bb3bd98f87926eb129eb1736dfe818c67b3b81ef7ce4edd0b3cd` |
| `share/bios-256k.bin` | `ae6f6aa973aaccc143f57aa960fb035fd9de4daee4ad0cd713322f8c259e7650` |
| `share/linuxboot_dma.bin` | `9c49e255340c78fc12e54ed043462bca02fb7fca29b7cfab62ff88a5344b6950` |

The local acquisition manifest has SHA-256
`1ae600425349ee30ad6dbc8e2086b75d77264286d589ff63043e4ba9be81c90b`.
Its deterministic runtime ZIP is 43,191,350 bytes with SHA-256
`d4523a2752810e0e8a01bb0f3559c33a140dd6ab63dd6a1a5060833ffa3edb45`.
These are evidence for the locally prepared subset, not separate upstream
download artifacts. The product catalog should retain the individual runtime
file hashes and the original upstream installer identity.

## Implemented v3 custody invariant

The profile identity is
`qemu-11.1-fixed-argv-medium-job-single-byte-no-vapic-v3`.

Before any emulator instruction executes, the supervisor verifies and retains
custody of the exact executable, dependency closure, firmware, kernel and job
initramfs. Its runtime namespace is administrator-owned under Program Files,
with a protected ACL excluding ordinary-user file creation or modification.
Leaf read handles deny writes/deletion throughout execution. Ancestor directory
custody excludes alias substitution. Source input cannot supply arguments,
configuration keys, host paths or environment values.

The supervisor creates the child suspended, assigns its kernel process handle
to a kill-on-close Job Object with one-process, 2 GiB process-memory and 25%
host-CPU limits, verifies the
intended executable/token, and resumes only after those boundaries succeed.
Dedicated inherited anonymous standard-I/O handles carry serial output and the
READY/start exchange described below. Kernel handles, rather than a PID alone, identify
and terminate the exact child.

Direct kernel/initramfs boot exposes zero guest block devices; the existing
guest validator accepts this inventory. The fixed profile supplies
`-no-user-config`, `-nodefaults`, `-display none`, `-monitor none`, `-nic none`,
`-parallel none`, a dedicated serial channel, and `-no-reboot`, plus an exact
`pc-i440fx-11.1` machine model, 768 MiB memory, one virtual CPU and explicitly
selected single-threaded TCG emulation.
No automatic accelerator fallback, user configuration, monitor multiplexing,
shared filesystem, USB device or arbitrary plugin is accepted. The guest still
waits for GO before analyzing static copied source. These design choices are
based on the [QEMU invocation documentation](https://www.qemu.org/docs/master/system/qemu-manpage.html).

The fixed `-global apic.vapic=off` option disables an unnecessary option-ROM
device. QEMU's [APIC initialization](https://raw.githubusercontent.com/qemu/qemu/v11.1.0/hw/intc/apic_common.c)
realizes the ordinary APIC before conditionally creating the VAPIC device.
Only that optional device's
[realization](https://raw.githubusercontent.com/qemu/qemu/v11.1.0/hw/i386/vapic.c)
requests `kvmvapic.bin`. The explicit property therefore removes that lookup
while retaining ordinary APIC interrupts and timers. The reviewed runtime
remains **109 files with two ROMs**, matching the protected installation;
there is no reliance on a missing-file fallback or extra privileged copy.

## Native serial handshake correction

The first real guest reached READY, then failed after its 45-second input
deadline. Host output showed only a truncated prefix of the 36-byte GO line.
The pinned [Windows stdio backend](https://raw.githubusercontent.com/qemu/qemu/v11.1.0/chardev/char-win-stdio.c)
explains this behavior: its worker reads one byte at a time, and the main-thread
callback acknowledges the worker even when the emulated UART cannot accept
the byte. A burst can therefore lose bytes before Linux receives a complete
canonical input line.

The implemented guest opens its serial input and enables cbreak mode before
printing READY, then accepts exactly `b'G'` from the host. Cbreak permits a
single-byte read and disables echo; performing it before READY also avoids
discarding the host reply through the default input flush.
[Python terminal mode semantics](https://docs.python.org/3/library/tty.html).
The host writes only after establishing process identity and resource limits.
The exact per-job UUID remains mandatory in READY and the validated report;
the exclusive inherited pipe carries start authority. The fix does not use
timing-based byte pacing or relax report validation.

## Search-path and dependency findings

The [QEMU module loader](https://raw.githubusercontent.com/qemu/qemu/v11.1.0/util/module.c)
consults `QEMU_MODULE_DIR` before its compiled module location. Construct a
minimal environment and do not forward QEMU, GLib or plugin overrides. Derive
the native dependency closure from the actual package, including delay imports
and dynamically loaded modules used by the fixed profile.

The [firmware locator](https://raw.githubusercontent.com/qemu/qemu/v11.1.0/util/datadir.c)
checks the current directory before configured firmware directories.
[Startup](https://raw.githubusercontent.com/qemu/qemu/v11.1.0/system/vl.c)
also appends compiled firmware fallback directories. Use the operating system's
actual System32 directory as the working directory; pin the explicit BIOS and
firmware directory. Direct x86 kernel boot still requires BIOS and boot-ROM
assets, so kernel/initramfs hashes alone are insufficient.

A leaf seal does not prevent creation of a new DLL filename elsewhere in a
writable search directory. Namespace protection is therefore required in
addition to manifest checking. A loaded-module inventory is useful native
evidence but cannot replace preventive custody after code has already run.

## Native acceptance status

The coordinator's v3 native run executed both real analyzers and received valid
reports without missing-ROM warnings. Both reported loopback only, no external
network adapters, zero block devices and no host shares. Bandit produced the
expected B101 finding. Gitleaks completed without errors but returned no
findings for the original alphabetical test token: its pinned
[global allowlist](https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/config/gitleaks.toml)
explicitly ignores the alphabet sequence, and
[stopword matching](https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/config/allowlist.go)
is case-insensitive. `/input/00000.txt` is not an excluded path.

The coordinator replaced that fixture with a locally generated SHA-256-derived
36-character hexadecimal value following `ghp_`; no credential was obtained or
issued. The repeated complete real-analyzer readiness check passed both
expected-detection gates. Executing Gitleaks and receiving a valid empty report
did not satisfy the earlier gate. The coordinator also verified a complete
source scan, redacted history and GUI report, and cancellation with exact-child
cleanup; see [native acceptance](native-lab.md).

Require real Bandit and Gitleaks fixture receipts, the expected loopback-only
network inventory, zero block devices and no host shares. Check cancellation,
timeout, output bounds, memory/process limits and complete Job Object teardown.
Adversarial fixtures should cover changed runtime DLLs, firmware, kernel and
initramfs; hostile working directories/environment; reports before GO; and
cancellation before process resume. Readiness must bind the backend profile,
runtime manifest and guest image identity.

Static acquisition and dependency evidence alone are not native acceptance.
The research/acquisition reviewer did not execute QEMU, start a VM, install a
runtime, change services or invoke UAC; the coordinator owns the native runs.
