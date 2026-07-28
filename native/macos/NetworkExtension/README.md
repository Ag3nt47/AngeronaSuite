# Network Extension containment phase

Angerona's macOS Observe preview does not install a content filter and does not
claim network containment. A later Protect edition can add a Network Extension
content-filter provider after:

- a signed containing app and approved Network Extension entitlement exist;
- flow classification is separated from user content;
- allow/deny policy has deterministic local fallback behavior;
- VPN, captive portal, update, DNS, loopback, and uninstall failure modes pass;
- operators can see and reverse every containment decision.

The Python core should receive only normalized flow metadata. It must never be
placed synchronously in the network data path.
