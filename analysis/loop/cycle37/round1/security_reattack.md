# Cycle 37 Round 1 security reattack

The detailed [read-only Red Team findings](redteam_findings.md) and
[machine-readable handoff](redteam_findings.json) cover four new issues on
`795cc55`: two medium-severity Shark drill object-custody/data-loss paths and
two low-severity report-history/cleanup responsiveness paths. Both data-loss
paths and the unsigned-history display were reproduced with inert temporary
files. No new Combat/Purple/FIM false-credit route was confirmed in this pass.

This report records discovery evidence. Remediation, tests, combined release
validation, and publication belong to the maintainer's follow-up cycle.

## Independent candidate-fix reattack

In a separate Python process with disposable Windows files, the current
in-progress Shark patch refused the pre-placed BYOVD hardlink without changing
the unrelated document; its step recorded `ok=False`. It preserved both an
unrelated same-name replacement and the renamed original during Stop & clean,
while still removing an unchanged owned marker. These are targeted closure
probes for R37-01 and R37-02, not a full drill or release gate.

The in-progress archive viewer rejected unsigned forged JSON, changed signed
text, hardlinked and oversized members, and a copied old signed report renamed
to a 2099 archive name. A separate offscreen console run listed and displayed
one authentic signed report, skipped an invalid-date filename, and showed an
authenticity error rather than forged text when the false report was selected.
That standalone process needed an explicit Qt history-pool drain before clean
exit; the parent-owned focused pytest suite exited. Windows symlink creation
was unavailable for an independent symlink fixture, so that case was reviewed
in code only. Targeted results support candidate closure of R37-03 and the
GUI portion of R37-04; Shark's bounded-scan portion is still a code-path
review pending combined tests.
