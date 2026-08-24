## What changed

Describe the user-visible outcome and the problem it solves.

## Safety and scope

- [ ] The change is defensive, authorized, local-first, and bounded.
- [ ] New egress, elevation, retention, or remediation behavior is documented.
- [ ] No runtime data, credentials, private telemetry, or generated secrets are included.
- [ ] Platform capability claims remain accurate.

## Verification

- [ ] Focused regression tests were added or updated.
- [ ] `python -m compileall -q src tests tools` passes.
- [ ] `python -m pytest -q` passes, or the exact limitation is explained below.
- [ ] UI changes were checked at the minimum supported size and with motion disabled.

## Screenshots / notes

Use synthetic or manually redacted data only. Link the related issue and note
any follow-up work or known limitation.

