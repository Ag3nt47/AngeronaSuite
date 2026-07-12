# Streamline — done 2026-07-02

Consolidated the project into one tree rooted at **`AngeronaSuite/`**.

## Backup (on F, before anything was touched)
`F:\Angerona-Backups\streamline-20260702\`
- `Angerona-legacy\` — verbatim copy of the old `Angerona/` folder (19 files, incl. the fuller 808-line `shark_attack.py`).
- `AngeronaSuite-source.tar.gz` — full Suite source snapshot (excl. venv/caches).

## Done
- **Legacy `Angerona/` hard-deleted** from D (folder now empty). It was already superseded by `src/angerona/shark/`; preserved on F.
- **Deleted rebuildable cruft** from the Suite: `venv/` (~700 MB), 182 `__pycache__/`, ~1,517 `*.pyc`, `angerona.egg-info/`. **Result: 711 MB → 3.7 MB.** All 87 source `.py` files intact. Rebuild venv with `install.bat`.

## Deliberately NOT changed
- **Loose root scripts left at root** (`install.bat`, `run.bat`, `build.bat`, `start-angerona.bat`, `mitigation_gate.ps1`, etc.). They are root-anchored launchers: each does `cd /d "%~dp0"` then references `venv\`, `src\angerona\`, `assets\`, `.[windows]`, and each other by root-relative paths. `mitigation_gate.ps1` is also invoked from the Python mitigation pipeline (`defense_monitor.py`, `playbook_tuner.py`). Moving them into `scripts/` would break those paths and require an untestable rewrite of ~10 files for no functional gain.
- `.env` (gitignored, holds API keys), all real source, `diagnostics/`, `rules.yar`, `yara64.exe`, `frz/`, `hermetic/`, `syscall_bridge/`.
