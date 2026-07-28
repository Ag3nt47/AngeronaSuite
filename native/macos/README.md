# Angerona macOS native sensor boundary

This directory is the native half of the macOS sensor architecture. It is
source scaffolding for an Xcode workspace, not a pre-signed binary and not a
claim of active enforcement.

## Intended service graph

1. `AngeronaHost` is a signed, notarized menu-bar or background host.
2. The host asks macOS to activate `org.angerona.EndpointSecurityExtension`
   through `OSSystemExtensionRequest`.
3. The Endpoint Security extension subscribes to notification events and sends
   a minimized event envelope to the host over authenticated XPC. The host's
   `FSEventsObserver` supplies asynchronous file-change metadata and preserves
   rescan/overflow flags rather than hiding a coverage gap.
4. The host signs the normalized frame with the installation bridge key and
   forwards it over a current-user, owner-only Unix socket to the Python core.
5. `AuthenticatedNativeBridge` verifies the HMAC, timestamp, nonce, platform,
   size, and normalized schema before EventBus publication.

The initial edition is **Observe**: it can report process/file security
telemetry but does not authorize, block, quarantine, isolate, or delete. Adding
an `ES_EVENT_TYPE_AUTH_*` subscription is a later, separately reviewed
protection phase.

## Apple gates before distribution

- Request Apple's Endpoint Security client entitlement for the Developer ID
  team and provisioning profile.
- Build the system extension and containing host with the hardened runtime.
- Use a stable Team ID and bundle identifiers; never ship the placeholder IDs.
- Sign all nested code in the correct order, notarize the containing app, and
  staple the ticket.
- Package activation, deactivation, upgrade, and uninstall paths in the host.
- Complete privacy review for every collected field. Command lines, usernames,
  file contents, and full URLs remain off by default.
- Validate on supported macOS versions in a VM and on physical Apple Silicon.

For development, create a normal macOS App target and an Endpoint Security
System Extension target in Xcode, then add the Swift files in this directory.
Xcode owns signing assets and the generated project file; no private certificate
or provisioning profile belongs in this repository.

Official Apple references:

- Endpoint Security: https://developer.apple.com/documentation/endpointsecurity
- Entitlement: https://developer.apple.com/documentation/BundleResources/Entitlements/com.apple.developer.endpoint-security.client
- System Extensions: https://developer.apple.com/documentation/systemextensions
- SMAppService: https://developer.apple.com/documentation/servicemanagement/smappservice
- Notarization: https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution
