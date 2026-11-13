# Windows service and signing setup

The native third watchdog can be built without Python. Its Windows service
entry and the installer preparation tools are source support, not a signed
release or a completed enterprise installer. The repository has no provisioned
production publisher or independent release authority. Nothing in this guide
grants installation authority or activates protection.

## Obtain a signing identity

For distribution through GitHub, the recommended starting point is Microsoft's
[Azure Artifact Signing](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart)
(formerly Trusted Signing). In your own Azure account:

1. Create an Artifact Signing account in a supported region.
2. Complete **Public Trust** identity validation in the Azure portal.
3. Create a **Public Trust** certificate profile and assign its signer role to
   the separately governed publishing identity.
4. Keep signing credentials outside this repository and its candidate runners.

Individual public-trust validation currently requires a US or Canadian identity.
Use the official quickstart for current eligibility and billing requirements.
Identity verification and paid account enrollment are actions for the account
owner. Do not send identity documents, passwords, PFX files or private keys to
an assistant or commit them. Cloud signing does not require a certificate to
appear in this development computer's local certificate store.

Microsoft documents the [SignTool integration](https://learn.microsoft.com/en-us/azure/artifact-signing/how-to-signing-integrations).
The public account endpoint, account name and certificate-profile name are
configuration metadata; possession of them is not signing permission. The
publishing service must also authenticate and authorize the exact reviewed
release. Short-lived signing certificates require the documented timestamping
procedure and verification of the signed final bytes.

Other options are a trusted CA's hardware-backed code-signing certificate or
Microsoft Store MSIX distribution. Store package signing alone does not satisfy
Angerona's separately pinned executable signatures and release authorization.
See Microsoft's [signing comparison](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options).
Free OSS signing programs require eligibility review: SignPath Foundation's
[terms](https://signpath.org/terms) exclude some active security-diagnosis tools,
so Angerona must not assume acceptance or try to evade those terms.

## Prepare the installer integration for review

Run the diagnostic from the repository in Windows PowerShell:

```powershell
.\tools\Get-AngeronaServiceReadiness.ps1 -AsJson
```

This observes named SCM registrations, matching-name packages for the current
user, the development
watchdog's signature status and local certificate counts. It never reads keys,
starts a candidate, enrolls trust, requests UAC or changes a service. A matching
name or `Valid` signature does not prove the approved publisher. Even with all
objects present, it reports activation as unverified.

`tools/prepare_windows_service_request.py` creates a canonical, explicitly
untrusted review request tied to a supplied source commit. Its output describes
the fixed service profiles and remaining acceptance requirements; it contains
no executable installer commands and is not the watchdog's runtime config.
The external publisher must independently check the source, identities, final
signed bytes and installer implementation rather than treating this request
as authority.

Supply a reviewed commit in the following command; the output parent must
already exist and the filename must be new:

```powershell
python tools/prepare_windows_service_request.py --source-commit REVIEWED_40_CHARACTER_COMMIT --output service-review-request.json
```

Replace the commit placeholder with the actual 40 lowercase hexadecimal
characters. A successful exit means the request was written, not that the
source or installation was approved.

## Preserve the two different service profiles

| Component | Required SCM entry | Account | SID policy |
| --- | --- | --- | --- |
| Engine | `Angerona.exe --engine-service` | `NT SERVICE\AngeronaProtection` | Restricted, type 3 |
| Third watchdog | `watchdog3.exe --service` | LocalSystem | None, type 0 |

Both use their fixed names (`AngeronaProtection` and `AngeronaWatchdog3`) and
own-process service type. The third watchdog's SCM host is independent of
Python's child Job. It checks its actual registration/process/token before
running the existing supervisor, and SCM stop/shutdown cancels that supervisor.
It never installs, configures, stops or kills the engine. Normal successful
engine stops remain stopped.

The watchdog uses LocalSystem because the engine's current SCM ACL permits
start authority only to SYSTEM, Administrators and TrustedInstaller. This is a
privileged supervisor; it is not a new isolated virtual-account profile. Do not
add a broad service-start grant to make a different account pass. The engine's
own restricted account and all of its admission rules stay unchanged.

Microsoft's [MSIX service schema](https://learn.microsoft.com/en-us/uwp/schemas/appxpackage/uapmanifestschema/element-desktop6-service)
can specify only LocalSystem, LocalService or NetworkService. It cannot express
the required engine virtual account. A simple manifest service entry therefore
does not complete this installation. The separate governed installer must
prove OS-bound package identity together with the actual restricted service
token in a disposable Windows VM. Ordinary `CreateService` registration alone
does not establish that proof. Until accepted, the enterprise apply profile
remains unavailable; the existing migration-only Setup is not a first installer.

## What the protected installer must provision

The independently reviewed installer needs the exact signed package, immutable
publisher/package identity and final executable pins. It must verify protected
file custody through mutation and execution, not hash user-writable files and
trust their paths afterward. It must refuse unrelated existing service names,
retain operator STOP and key material, preserve preferences and recover from a
partial installation without deleting prior state.

The engine's private state remains the native ProgramData known folder's
`Angerona/Protection`, with SYSTEM, Administrators and the engine service SID
as its admitted writers. The watchdog's six-field schema-2 configuration remains
`Angerona/watchdog3/config.json` under that same known folder. It points to a
**separate** private watchdog runtime with its own installer-provisioned
`shutdown.key`. Never reuse the engine's private root or copy an ambient user
key. The watchdog runtime can be on a protected D: directory; this does not
relocate the engine's fixed root or the fixed configuration discovery path.

The installer must also own service upgrade, removal, bounded failure recovery,
and rollback of only its newly created objects. It must not silently overwrite
another registration, clear signed STOP, install a root certificate or start a
development build. A real UAC approval is needed for installation, in addition
to the publisher and package checks.

## Complete signing and acceptance

Follow the existing [release signing boundary](RELEASE_SIGNING_BOUNDARY.md).
Windows Authenticode signing and the two independent Ed25519 release signers
are separate requirements; an Artifact Signing account supplies neither the
release threshold nor an installer implementation automatically.

The independently governed publisher must sign the final native watchdog
first, embed its final SHA-256 and exact approved publisher in the frozen
application, and inject the approved package identity before freezing. It
must then sign the core and startup helper, rebuild SafeStart with the signed
helper digest, sign SafeStart, and construct/verify the final catalog, MSIX and
release authorization. Any later signing change invalidates earlier byte pins.
Candidate repository scripts and hashes remain untrusted inputs throughout.

Acceptance must use an isolated Windows VM with the intended signed package:

1. Verify the actual engine account, Session 0, restricted service SID, process
   ACL, OS package identity, native image and private-state custody.
2. Provision and validate the separate watchdog authority/configuration. Run
   its read-only `--validate-only` check before starting its SCM host.
3. Prove SCM startup, exact process generation, supervisor output and native
   retirement on stop/shutdown. Confirm that manual console `--service` fails.
4. Exercise failed-engine recovery, ordinary clean stops, signed STOP, pending
   starts, missing/tampered authority and duplicate-supervisor prevention.
5. Verify reboot, preference-preserving upgrade, partial-install rollback and
   uninstall. Preserve evidence when a check is unavailable or inconclusive.

Passing offline unit tests does not replace those deployment checks. The
repository's release workflow continues to stop before public signed assets
until the independent authority and service installer have been provisioned
and accepted.
