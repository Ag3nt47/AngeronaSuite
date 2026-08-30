# Cycle 26 round 1 adversarial findings

Scope: authorized, defensive-only theoretical hardening. No live intrusion, persistence, credential access, or weaponized exploit was attempted.

The first pass confirmed seven defects or residuals: three high-severity
privileged source-install trust failures, a medium release-signing separation
residual, and three medium-severity runtime assurance failures involving
resilience self-test custody, Scan Center path-object binding, and truthful
multi-scanner status. Machine-readable remediation gates and exact affected
locations are recorded in `redteam_findings.json`.

The Windows source installer and convenience launcher findings share one root
cause: a writable source checkout cannot safely become its own elevated trust
authority. `run.bat` delegates to the same source launcher, so it is inside the
same boundary. The required design is a signed, OS-validated packaged first
install; development/source setup must remain non-elevated and must report its
reduced observation coverage honestly. The scan findings require object-bound
I/O and honest aggregate state rather than stronger wording around a pathname
race.

Separate work in this round also treats the requested sub-100% module evidence as security-sensitive UI: evidence navigation must be internal, bounded, read-only, and restricted to governed source references.
