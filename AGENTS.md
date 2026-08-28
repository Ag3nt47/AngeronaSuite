# Angerona repository instructions

## Publication completion

For every completed maintainer-authorized Angerona update, commit, version
upgrade, or release-documentation change, “done” includes GitHub publication.
Run the relevant offline validation, commit only the reviewed in-scope files,
and publish through `python tools/publish_github_update.py` (or the guarded
`push-to-github.bat` wrapper). Invoking this publisher is explicit maintainer
authorization to atomically fast-forward public `main` to the completed,
reviewed current commit; never invoke it for work in progress. The publisher
must prove all of the following before completion is reported:

- the exact canonical `Ag3nt47/AngeronaSuite` HTTPS origin is in use;
- the current branch and GitHub's default `main` both equal local `HEAD`;
- `main` advanced only by fast-forward and the worktree stayed clean; and
- every repository-relative README image is tracked, valid, reachable from the
  public `main` branch, and byte-identical to the checked-out file.

A local-only commit, an unverified push, a feature-branch-only update, or a
missing public asset is incomplete. Never force-push or silently merge, rebase,
or reset a diverged `main`; stop and report the exact divergence for explicit
maintainer review.
