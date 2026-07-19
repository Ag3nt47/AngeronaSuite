# Security policy

## Supported releases

Security fixes are made against the current release line. Use the newest
checksummed, provenance-attested GitHub release and verify its published
SHA-256 checksum and build attestation. Current builds are not Authenticode
signed, so Windows may display **Unknown Publisher**.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability or exposed
secret. Use GitHub's **Security → Report a vulnerability** private advisory form
for this repository. Include the affected version, reproduction steps, impact,
and any safe proof of concept. Remove credentials, personal telemetry, and
unrelated host data before attaching logs.

We will acknowledge a report as soon as practical, validate it, coordinate a
fix, and credit the reporter unless anonymity is requested. Do not access data
that is not yours, persist on another system, or disrupt services while testing.

## Trust boundaries

Angerona is defensive software that may run elevated to observe Windows
telemetry. Source checkouts are development environments, not privileged trust
roots. Prefer packaged releases; keep the install directory administrator-owned;
and install third-party dependencies only through the installer or release
workflow. Optional network features are off by default and must be configured
with explicit destinations and allowlists.

Red-team simulations create inert markers only. They are not authorization to
run real exploits, steal credentials, establish persistence, or test systems you
do not own or administer.
