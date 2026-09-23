# Native Analysis Lab acceptance — September 23, 2026

The current Windows Intel/AMD QEMU backend passed both real guest readiness
fixtures and an end-to-end source analysis, report display and cancellation
check. This evidence applies to the reviewed QEMU profile; it does not change
the VMware backend's configuration-write incompatibility.

## Exact accepted runtime

- QEMU 11.1.0, protected administrator-owned 109-file runtime, 127,443,388 bytes.
- Profile: `qemu-11.1-fixed-argv-medium-job-single-byte-no-vapic-v3`.
- Catalog version 2, Bandit 1.9.4 and Gitleaks 8.30.1.
- Deterministic base guest: 24,415,754 bytes, SHA-256
  `3527278483488d153a62bdc6ad4b298bedb8b4a7172ece5f0adb7ec7b6a44e31`.
- Normal, non-administrator Windows session; source was inert test data.

The emulator, recursive DLL closure and two required ROMs passed exact file-set,
size, hash, owner, ACL and held-file custody checks. The native supervisor
started each child suspended, verified its medium token and exact image,
assigned its resource-limited Job Object, and resumed it before accepting the
guest READY handshake. The fixed profile disables the unused VAPIC feature;
neither accepted analyzer emitted missing-ROM warnings.

## Real readiness fixtures

| Analyzer | Expected finding | Elapsed | Peak emulator RSS | Reaped |
| --- | --- | --- | --- | --- |
| Bandit | B101 | 117.328 s | 408,109,056 bytes | Yes |
| Gitleaks | github-pat | 62.593 s | 472,223,744 bytes | Yes |

Both reports passed schema, job identity, input/catalog identity and isolation
validation. Both reported zero analyzer errors, loopback as their only network
interface, zero block devices and no host shares. Observed mapped modules came
only from the protected runtime or Windows System32/WinSxS. No QEMU process
remained afterward. `readiness()` returned true for the saved current-catalog
selfcheck.

The original alphabetical secret fixture was legitimately suppressed by the
pinned Gitleaks global allowlist. Its empty report was rejected by the expected
detection gate. A deterministic SHA-256-derived, never-issued fixture replaced
it, and the complete two-analyzer readiness check was rerun successfully.

## Source, history, cancellation and GUI

A normal `run_analysis(..., 'gitleaks')` call scanned a copy of an inert local
UTF-8 source file in **47.719 seconds**. It reported the expected `github-pat`
finding, mapped the opaque guest filename back to `sample.txt`, and saved one
history receipt. Neither the receipt nor GUI report contained the fake secret.
The report's origin remained `external_analysis` with `response_authority=False`.

A second run was cancelled one second after native child creation. It raised
the expected cancellation exception, reaped the exact owned child, saved no
additional history entry, and left no job copy after cleanup. Readiness stayed
true. The offscreen Qt panel displayed Ready, the existing history entry and
the redacted finding; the captured panel was visually inspected.

Private diagnostic artifacts remain outside version control under
`.tmp/continuation-20260923/`: `qemu-native-check.json`,
`qemu-end-to-end.json` and `lab-native-report.png`. They are local evidence,
not public repository assets or fixtures required by the product.

## Performance and scope

The Lab creates an emulator only for explicit analysis/readiness jobs. No Lab
VM runs while Angerona is idle. The guest has one virtual CPU and 768 MiB RAM;
the host process has below-normal priority, a 25% total-host CPU cap, 2 GiB
memory cap, one-process Job Object and five-minute job deadline. Measurements
above describe this host, not a general speed guarantee.

Diskless refers to guest devices. Host source snapshots, redacted reports,
runtime artifacts, Windows paging and crash dumps still exist. Runtime setup
is optional and requires normal Windows consent for protected installation.
The Lab currently requires 64-bit Intel/AMD Windows and a normal user session;
native macOS/Linux guest execution and arbitrary submitted-code execution are
not provided by this backend.
