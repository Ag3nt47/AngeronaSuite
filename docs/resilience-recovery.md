# Component heartbeats and mutual recovery

Angerona starts its peer watchdog, telemetry scanner and enabled Black Box
recorder through the existing resilience supervisor. The watchdog supervises
the core in return. Both sides use adoption, shared spawn coordination, retained
process identity and bounded backoff to avoid duplicate or repeated launches.
These processes share the host and user-mode trust boundary; this is not an
independent security appliance or kernel guarantee.

## Read the footer

Click the EKG strip beside CPU/RAM/network status for component details.

| Display | Meaning |
| --- | --- |
| Green beating trace | A real authenticated heartbeat advanced for the observed native process generation and is still fresh. |
| Red flatline | A usable heartbeat is missing, stale, stopped, disabled, starting or unavailable. Details distinguish the reason. |
| Additional helpers | Open details for separate monitors, inventory and local AI. A helper without a compatible progress heartbeat remains explicitly unavailable; process presence does not manufacture a pulse. |

The core, Python peer watchdog and scanner publish their existing authenticated
progress signals. Black Box now beats from its real Qt event loop, so an
independent timer thread cannot mask a frozen recorder window. The background
observer checks exact process generations and advancing counters; the footer
copies memory and expires old observations without inspecting the host on Qt.
A pulse establishes recent liveness, not sensor completeness, threat absence,
trusted code or response authority. Native external watchdogs use a separate
protocol and are labeled when a compatible component heartbeat is unavailable.

## Check or request recovery

For an ordinary-user Windows source checkout, open a terminal in the repository:

```powershell
.\Ensure-Angerona-Recovery.bat --check-only
```

Check-only does not create keys, start a core, publish restart requests or change
preferences. The result reports whether authenticated supervision was observed;
it does not claim protection. A held or unavailable result returns a nonzero exit.

To request a bounded repair through the existing supervisor:

```powershell
.\Ensure-Angerona-Recovery.bat
```

With a verified active core and fresh authenticated supervision, the helper can
request missing enabled peers through their existing authenticated restart
inboxes, then observe briefly for recovery. It creates no competing manager or
daemon and terminates no process itself. Disabled Black Box stays disabled.
If no core owns the instance lease, the helper can request the normal guarded
source launcher with automatic-start inhibition. A launch request is not proof
that a dashboard or protection engine became ready.

An existing STOP or ambiguous maintenance record holds this helper. To resume
after intentional STOP, run the normal explicit `start-angerona.bat` launcher.
A STOP arriving during a helper-requested launch must remain effective. An
active core without authenticated supervision requires a controlled restart:
use dashboard STOP or tray Quit, then the normal launcher. The helper does not
guess a process to kill or attach a new manager to an existing core.

Repeated failures retain backoff and crash-loop state. The supervisor retries
eligible non-faulted state after its cooldown. Unknown authority, unsafe paths
and unresolved ownership remain held; they are not cleared to make an indicator
green. Inspect the private diagnostic explanation if recovery is still unavailable.

## The October 28 launch defect

The affected supervisor supplied the entire inherited environment as strict
child overrides. The environment validator rejected `APPDATA`, preventing the
watchdog, scanner and Black Box from spawning. The corrected adapter supplies
inherited values through the allowlisted source path. Credentials, proxies and
Python path controls remain excluded; explicit unsafe overrides remain rejected.
Existing failure evidence and keys are preserved.

See [Safe Startup](safe-startup-recovery.md) for runtime/source recovery and
[security flow](security-flow.md) for STOP, authority and coverage boundaries.
Source publication does not update previously installed signed binaries; those
require their separate accepted build, signing and installation process.
