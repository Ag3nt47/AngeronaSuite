# Prior findings (do NOT re-report unless still unfixed)

From the comprehensive security self-assessment (analysis/Angerona_Security_Assessment_v2.0). The red-team agent should VERIFY these against the current code, and only re-raise one if it is genuinely still exploitable.

| ID | Title | Component | Status |
|---|---|---|---|
| A-01 | Autonomous execution of AI-generated Python (syntax-check only) | engines/self_compiler.py, modules/evolution_engine.py | MITIGATED — off by default (`ANGERONA_SELF_EVOLVE`) + static denylist scan in `hot_reload_capability` |
| A-02 | MCP server: wildcard CORS + no auth | engines/mcp_server.py | MITIGATED — wildcard CORS removed; `_guard()` loopback-Host check + optional bearer token |
| A-03 | CVE fix advisor executes AI-generated PowerShell | core/cve_fix_advisor.py | MITIGATED — `scan_powershell` destructive denylist at analyze + apply |
| A-04 | Drop-in module loader auto-executes any .py at startup | core/module_manager.py | OPEN (by design) — needs drop-in dir ACL check + trust-boundary docs |
| A-05 | shell=True with interpolated PID in forensics | modules/forensics.py | MITIGATED — argv-list netstat + Python filter, no shell |
| A-06 | Broad `PowerShell -ExecutionPolicy Bypass` usage | engines/*, modules/* | OPEN — centralize/allowlist/log PowerShell execution |
| A-07 | SHA-1 used for a path identifier (non-security) | modules/shadow_shield.py | OPEN (cosmetic) — SHA-256 for consistency |

Recently added (already present — do not propose as "new"): core/alert_ack.py + threat-level exclusion, gui/resolve_center.py, gui/red_team_console.py (intensity/campaign/history), gui/incident_timeline_page.py, gui/attack_heatmap.py (Coverage/Top tabs), core/cve_ignore.py, core/cve_fix_advisor.py, core/ir_bundle.py, modules/daily_briefing.py, modules/lsass_guard/beacon_detector/shadowcopy_guard/usb_monitor.
