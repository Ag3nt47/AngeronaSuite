# QEMU Analysis Lab independent boundary review

Scope: the new supervisor, protected runtime verification, analysis-job
integration and optional privileged setup. This is a read-only code review;
only this report was authored. Findings were sent to the responsible engineers
before native acceptance. All three findings below were corrected by the
responsible engineers and independently re-reviewed. Native guest acceptance
results are recorded separately by the coordinator.

## Confirmed findings

1. **Generated setup archive lacked independent catalog validation at its seal.**
   `_bundle` closed its writer before acquiring a deny-write/delete read handle,
   then calculated the archive digest from the file occupying that pathname.
   A substituted archive could therefore become the digest authorized for the
   privileged copy. The helper bounded names, member count and expanded size,
   but did not establish each member's catalog identity. Subsequent runtime
   validation would reject execution, so this was not an established guest or
   administrator code-execution bypass. It nevertheless broke the claimed
   reviewed-bytes boundary for privileged copying. **Corrected:** while holding
   the archive seal, `_verify_bundle` validates the exact member set and count,
   rejects duplicates and encrypted members, and checks each bounded member's
   size/hash against `FILES` before authorizing the whole-archive digest.
   Independent in-memory checks accepted reviewed bytes and rejected
   substituted contents, duplicate names, extra members and renamed members.

2. **Privileged destination ancestry used snapshots without retained custody.**
   `Assert-PlainChain` checked directory attributes but did not retain handles
   through protected-directory creation, extraction or recursive failure
   cleanup. The source-directory context in `_bundle` ended before its yield,
   while `_elevated` held only the PowerShell ancestry. A custom Program Files
   location with an ordinary-user-writable ancestor could therefore be renamed
   or redirected after checking. **Corrected:** the parent retains Program
   Files ancestor handles across the complete privileged operation. The
   elevated helper independently opens every ancestor from the filesystem
   root down without delete sharing and retains its `SafeFileHandle` objects
   through vendor installation, protected copying and cleanup, even if the
   parent exits. Its interop method comes from the already loaded Windows
   .NET Framework assembly; no writable temporary compiler input is used.

3. **Minimal inherited environment did not suppress compiled library config.**
   The pinned GnuTLS DLL contains a compiled build-host configuration path.
   QEMU initializes GnuTLS, and GnuTLS initialization consults its system
   configuration even when inherited environment variables are removed.
   **Corrected:** the supervisor explicitly sets
   `GNUTLS_SYSTEM_PRIORITY_FILE=NUL` and `OPENSSL_CONF=NUL`. It also sets
   `OPENSSL_MODULES` and `OPENSSL_ENGINES` to the protected non-directory
   runtime `COPYING`, suppressing compiled provider/engine directory defaults.
   This finding establishes unwanted external configuration consumption;
   arbitrary module execution through that specific GnuTLS path was not
   demonstrated.

The GnuTLS override is documented in its
[system configuration guide](https://www.gnutls.org/manual/html_node/System_002dwide-configuration-of-the-library.html)
and assigned directly in
[priority.c](https://raw.githubusercontent.com/gnutls/gnutls/3.8.10/lib/priority.c).
OpenSSL's
[configuration loader](https://raw.githubusercontent.com/openssl/openssl/openssl-3.6/crypto/conf/conf_mod.c)
uses `OPENSSL_CONF` instead of its compiled default; its
[environment documentation](https://docs.openssl.org/3.6/man7/openssl-env/)
defines the provider/engine directory overrides. The supervisor constructs
these values itself rather than forwarding user-provided values.

## Boundaries reviewed without a confirmed bypass

- The QEMU argument list is fixed. Copied source cannot add host disks, network,
  shared directories, monitor commands, configuration files or plugin options.
- The child starts suspended; Job Object limits and its same-user medium token
  and executable are verified before resume. Cleanup acts on owned kernel
  handles and falls back to termination of the exact created process.
- Kernel, generated initramfs and runtime files remain sealed throughout the
  supervised call. Runtime ACLs exclude unprivileged directory/file mutation,
  and the exact catalog file set excludes planted extra files.
- Reports are rejected before GO, including a report already buffered beside
  READY. The analysis layer independently validates report schema, uniqueness,
  job/input/catalog identity, allowed rules, source locations and isolation.
  Output, process count, memory, CPU and elapsed time are bounded.
- The Windows GIO module path derives from the DLL installation directory;
  the protected runtime excludes its module subtree and prevents its creation.
  [GLib module loader](https://raw.githubusercontent.com/GNOME/glib/main/gio/giomodule.c).
  QEMU's libcurl initialization occurs only when opening a curl-backed block
  device, which this profile does not provide.
  [QEMU curl driver](https://raw.githubusercontent.com/qemu/qemu/v11.1.0/block/curl.c).

## Native v3 corrections and acceptance boundary

The coordinator's native run exposed a startup failure that mocks did not:
READY arrived, but only a short GO prefix was echoed before the guest's
45-second timeout. The pinned
[Windows stdio implementation](https://raw.githubusercontent.com/qemu/qemu/v11.1.0/chardev/char-win-stdio.c)
acknowledges each worker byte even if the UART cannot receive it, explaining
loss from the original bulk write. The corrected guest configures cbreak input
before READY and accepts one `b'G'` byte through the exclusive inherited pipe.
UUID checks remain in READY and the final report, and the host still enforces
the process/token/Job Object gates before writing. Reports buffered before the
start byte remain invalid. The fix introduces no timing-only delivery claim.

The fixed profile now includes `-global apic.vapic=off`. In the pinned
[APIC initialization](https://raw.githubusercontent.com/qemu/qemu/v11.1.0/hw/intc/apic_common.c),
this property prevents construction of the optional VAPIC device after normal
APIC realization. Its
[ROM registration](https://raw.githubusercontent.com/qemu/qemu/v11.1.0/hw/i386/vapic.c)
therefore never runs. Ordinary APIC interrupts and timers remain available;
the installed **109-file, two-ROM** runtime needs no extra firmware or
privileged mutation. This explicitly removes an unused device instead of
accepting a missing-ROM fallback.

Both real analyzers subsequently executed and returned schema-valid reports
without ROM warnings. Their isolation inventories showed loopback only, no
external NICs, zero block devices and no host shares. Bandit reported B101.
Gitleaks reported no findings for the original alphabetical fixture because
its [pinned default config](https://raw.githubusercontent.com/gitleaks/gitleaks/v8.30.1/config/gitleaks.toml)
globally allowlists the alphabet sequence. The opaque `00000.txt` filename is
not excluded. A locally generated SHA-256-derived replacement fixture passed
the coordinator's repeated complete readiness run. **Both real analyzers now
pass their expected-detection gates.** The earlier empty Gitleaks report was
not accepted as a detection pass. See [native acceptance](native-lab.md).

The new `analysis_qemu_runtime.require_user_session()` wrapper preserves
`PermissionError` while giving Lab-specific wording to the existing
non-administrator check. Setup, runtime validation and analysis-job callers
use it without an import cycle or changed return contract. The UI already
displays `PermissionError` as bounded plain text. No new authorization or
exception-type regression was found in this wrapper review. An unrelated
mojibake regression in two analysis progress/readiness strings was reported
to the coordinator for correction.

A read-only native check of the supervisor's current-token and System32-path
adapters succeeded. No emulator was run by this reviewer. The coordinator's
native module inventories contained only protected runtime files and Windows
System32/WinSxS modules. Those observations support this fixed profile's native
acceptance; they do not replace preventive custody or prove every possible
future dynamic library load safe.
