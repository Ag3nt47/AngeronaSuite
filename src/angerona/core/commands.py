"""Interactive console backend — the command + AI prompt engine.

Parses a typed line and runs either a built-in incident-response command or,
for anything unrecognised (or `ask ...`), forwards it to the local AI. All
state-changing actions (kill/suspend/resume/priority) are defensive
incident-response on the local machine and are written to the audit ledger.
"""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import time
import urllib.request
from pathlib import Path
from typing import Callable, Dict, List

from angerona.core.eventbus import Event, EventBus, Severity

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

AI_SYSTEM = (
    "You are Angerona's built-in security assistant, embedded in a local EDR "
    "console. Answer concisely. The console supports these commands the user can "
    "run: help, ps, find <name>, kill <pid>, suspend <pid>, resume <pid>, "
    "prio <pid> <low|normal|high>, conns [pid], tree <pid>, modules, "
    "module <name> <on|off|restart>, threat, incidents, incident <id>, coverage, "
    "remlog [n|<T####>], aar, schtasks, services [filter], asn <ip>, lateral, "
    "reg <key>, dump <pid>, autoruns, portmap, "
    "academy (explain/stages/style/coach/"
    "achievements/profile/tune), ask <question>, clear. When a user "
    "asks how to do something, tell them the exact command."
)


class CommandConsole:
    def __init__(self, manager, bus: EventBus, config) -> None:
        self.manager, self.bus, self.config = manager, bus, config
        self._instructor = None    # lazy — angerona.academy.security_academy.FlightInstructor
        self._achievements = None  # lazy — angerona.academy.achievements.AchievementTracker
        self._cmds: Dict[str, Callable[[List[str]], str]] = {
            "help": self._help, "?": self._help,
            "ps": self._ps, "find": self._find,
            "kill": self._kill, "suspend": self._suspend, "resume": self._resume,
            "prio": self._prio, "conns": self._conns, "tree": self._tree,
            "modules": self._modules, "module": self._module,
            "threat": self._threat, "ask": self._ask_cmd,
            "test": self._test, "selftest": self._test, "stress": self._test,
            "query": self._query, "hunt": self._query, "sql": self._query,
            "aar": self._aar, "report": self._aar,
            "academy": self._academy,
            # Analyst-standard aliases + additions
            "netstat": self._conns, "contain": self._suspend, "isolate": self._suspend,
            "sessions": self._sessions, "whoami": self._sessions,
            "timeline": self._timeline, "iocs": self._iocs, "ioc": self._iocs,
            "search": self._search, "grep": self._search,
            "hashes": self._hashes, "hash": self._hashes, "sha256": self._hashes,
            "uptime": self._uptime, "env": self._env, "status": self._env,
            "incidents": self._incidents, "incident": self._incident,
            "coverage": self._coverage, "attack": self._coverage, "mitre": self._coverage,
            "remlog": self._remlog, "remediationlog": self._remlog, "actions": self._remlog,
            # Enterprise additions
            "schtasks": self._schtasks, "tasks": self._schtasks,
            "services": self._services, "svc": self._services,
            "asn": self._asn, "ipinfo": self._asn, "whois": self._asn,
            "lateral": self._lateral, "lm": self._lateral,
            "reg": self._reg, "registry": self._reg,
            "dump": self._dump_strings,
            "autoruns": self._autoruns, "persist": self._autoruns,
            "portmap": self._portmap, "openports": self._portmap,
            # ── new: threat-intel + AI + resources ──
            "intel": self._threat_intel, "threatintel": self._threat_intel,
            "fetchintel": self._threat_intel, "kev": self._threat_intel,
            "consult": self._consult_ai, "consultai": self._consult_ai,
            "research": self._consult_ai,
            "resources": self._resources, "resmon": self._resources, "load": self._resources,
        }

    # ── Entry point ──────────────────────────────────────────────────────────
    def run(self, line: str) -> str:
        line = line.strip()
        if not line:
            return ""
        try:
            parts = shlex.split(line)
        except Exception:
            parts = line.split()
        cmd, args = parts[0].lower(), parts[1:]
        handler = self._cmds.get(cmd)
        if handler:
            try:
                return handler(args)
            except Exception as exc:
                return f"error: {exc}"
        # Anything else → ask the AI.
        return self._ai(line)

    def _audit(self, msg: str, sev: Severity) -> None:
        self.bus.publish(Event("Console", msg, sev))

    def _proc(self, args: List[str]):
        if psutil is None:
            raise RuntimeError("psutil not installed")
        if not args:
            raise ValueError("usage: needs a <pid>")
        return psutil.Process(int(args[0]))

    # ── Threat intel / AI consult / resources ────────────────────────────────
    def _threat_intel(self, args: List[str]) -> str:
        """Summarise the latest CISA KEV threat intel the INTL module correlated
        to this host (shared_logs/upstream_threats.json). Read-only."""
        import json as _json
        from pathlib import Path as _Path
        repo_root = _Path(__file__).resolve().parents[3]
        path = repo_root / "shared_logs" / "upstream_threats.json"
        if not path.exists():
            return ("No threat-intel file yet (shared_logs/upstream_threats.json). "
                    "Ensure the 'Upstream Threat Intel Sync' (INTL) module is enabled "
                    "and online; it fetches the CISA KEV catalog and correlates it to "
                    "this host.")
        try:
            data = _json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            return f"Could not read threat intel: {exc}"
        items = data if isinstance(data, list) else data.get("threats", data.get("items", []))
        if not items:
            return "Threat-intel file present but no host-applicable CVEs right now."
        lines = [f"CISA KEV — {len(items)} host-applicable item(s), newest first:"]
        for it in items[:15]:
            cve = it.get("cve") or it.get("cveID") or it.get("id", "?")
            name = it.get("vulnerabilityName") or it.get("name") or it.get("product", "")
            due = it.get("dueDate") or it.get("due", "")
            rans = it.get("knownRansomwareCampaignUse") or it.get("ransomware", "")
            tag = "  ⚠RANSOMWARE" if str(rans).lower() in ("known", "true", "yes") else ""
            lines.append(f"  {cve}  {name[:60]}"
                         + (f"  (due {due})" if due else "") + tag)
        lines.append("Open the 🛡 THREAT INTEL dashboard for full detail + AI fix generation.")
        return "\n".join(lines)

    def _consult_ai(self, args: List[str]) -> str:
        """User-initiated ONLINE AI consult (Claude first, then fallbacks)."""
        if not args:
            return "usage: consult <question>   (reaches out to an online AI; Claude first)"
        prompt = " ".join(args)
        try:
            from angerona.engines.ai_consult import consult_ai
        except Exception as exc:
            return f"consult unavailable: {exc}"
        res = consult_ai(prompt)
        if res.get("text"):
            return f"[AI · {res.get('provider')}]\n{res['text']}"
        return (f"No AI answer ({res.get('error')}). Set ANTHROPIC_API_KEY (or another "
                "provider) in Settings ▸ API Keys, or ensure local Ollama is running.")

    def _resources(self, args: List[str]) -> str:
        """Per-module resource-intensity snapshot (heuristic: heaviness + live event
        activity). Mirrors the bottom ResourceStrip."""
        try:
            from angerona.gui.pages import _HEAVY_MODULES
        except Exception:
            _HEAVY_MODULES = set()
        activity: Dict[str, int] = {}
        try:
            for e in self.bus.recent(120):
                activity[e.module] = activity.get(e.module, 0) + 1
        except Exception:
            pass
        rows = []
        for name, mod in sorted(self.manager.modules.items()):
            running = getattr(mod, "status", "") == "running"
            if not running:
                pct = 0
            else:
                base = 42 if name in _HEAVY_MODULES else 16
                pct = max(1, min(100, base + min(52, activity.get(name, 0) * 8)))
            bar = "█" * (pct // 10) + "·" * (10 - pct // 10)
            rows.append((pct, f"  {pct:3d}%  [{bar}]  {name}"
                              + ("" if running else "  (stopped)")))
        rows.sort(key=lambda r: -r[0])
        return "Per-module resource intensity (0=idle/stopped → 100=heavy):\n" + \
               "\n".join(r[1] for r in rows[:40])

    # ── Help ─────────────────────────────────────────────────────────────────
    def _help(self, args: List[str]) -> str:
        return (
            "Angerona console — commands:\n"
            "  help                      this list\n"
            "  ps [n]                    top n processes by memory (default 15)\n"
            "  find <name>               find PIDs whose name matches\n"
            "  kill <pid>                terminate a process\n"
            "  suspend <pid>             freeze a process (containment)\n"
            "  resume <pid>              unfreeze a process\n"
            "  prio <pid> <low|normal|high>   change process priority\n"
            "  conns [pid]               active network connections (alias: netstat)\n"
            "  contain <pid>             isolate/freeze a process (alias: isolate; = suspend)\n"
            "  tree <pid>                process + its children\n"
            "  sessions                  logged-in users (alias: whoami)\n"
            "  timeline [n]              last n events, chronological (default 20)\n"
            "  iocs                      recent HIGH/CRITICAL indicators of compromise\n"
            "  search <term>             search recent events by text (alias: grep)\n"
            "  hashes <pid|path>         SHA-256 of a process image or file (alias: sha256)\n"
            "  uptime                    host + Angerona uptime\n"
            "  env                       config summary: Ollama host/model, data dir, modules\n"
            "  modules                   list modules + status\n"
            "  module <name> <on|off|restart>   control a module\n"
            "  threat                    current threat level + counts\n"
            "  incidents [n]             correlated incidents, newest first (risk-scored)\n"
            "  incident <id>             full timeline of one incident (id fragment ok)\n"
            "  coverage                  MITRE ATT&CK detect/simulate/remediate heatmap (alias: attack, mitre)\n"
            "  test [module]             run a self-test / stress drill (all, or one)\n"
            "  query <SELECT ...>        SQL threat-hunting over processes/connections/ports\n"
            "  aar                       print the latest Shark Attack After-Action Report\n"
            "  academy [sub]             Cyber Security Academy — coaching + achievements + tuning:\n"
            "      academy explain <stage>      teach one technique (Initial Access, Discovery,\n"
            "                                    Persistence (simulated), Noise Injection, Exfiltration)\n"
            "      academy stages               list technique names academy explain accepts\n"
            "      academy style <technical|analogy>   set Flight Instructor's explanation register\n"
            "      academy coach                Socratic post-mortem on the latest AAR's missed steps\n"
            "      academy achievements         show earned/unearned milestones\n"
            "      academy profile              one-shot EDR CPU/RAM overhead reading\n"
            "      academy tune                 show every real tunable knob + current value\n"
            "      academy tune <KEY> <VALUE>   change one (e.g. ANGERONA_NETMON_NOVELTY_WINDOW_MIN 15)\n"
            "  remlog [n]                remediation action audit log, newest first (alias: actions)\n"
            "  remlog <T####>            filter remediation log by MITRE technique\n"
            "  schtasks                  list Windows scheduled tasks (alias: tasks)\n"
            "  services [filter]         enumerate services + start type (alias: svc)\n"
            "  asn <ip>                  IP/ASN info — hostname, PTR record (alias: ipinfo, whois)\n"
            "  lateral                   lateral movement indicators from recent events (alias: lm)\n"
            "  reg <key>                 registry query — e.g. reg HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
            "  dump <pid>                extract ASCII strings from a process's virtual memory\n"
            "  autoruns                  suspicious persistence entries (Run/RunOnce/Winlogon, alias: persist)\n"
            "  portmap                   open listening ports mapped to process names (alias: openports)\n"
            "  intel                     latest CISA KEV threat intel correlated to this host (alias: kev, fetchintel)\n"
            "  consult <question>        consult an ONLINE AI (Claude first, then fallbacks) — user-initiated egress\n"
            "  resources                 per-module resource-intensity snapshot (alias: resmon, load)\n"
            "  ask <question>            ask the local AI\n"
            "  clear                     clear the console\n"
            "\nThreat-hunt tables: processes(pid,name,exe,ppid,username,mem_mb), "
            "connections(pid,status,laddr,raddr,lport,rport), ports(pid,proto,laddr,lport).\n"
            "  e.g.  query SELECT name,COUNT(*) c FROM processes GROUP BY name ORDER BY c DESC"
            "\nTip: any text that isn't a command is sent to the AI."
        )

    # ── Process inspection / response ────────────────────────────────────────
    def _ps(self, args: List[str]) -> str:
        if psutil is None:
            return "psutil not installed"
        n = int(args[0]) if args and args[0].isdigit() else 15
        rows = []
        for p in psutil.process_iter(["pid", "name", "memory_info", "username"]):
            try:
                mem = p.info["memory_info"].rss / (1024 * 1024) if p.info["memory_info"] else 0
                rows.append((mem, p.info["pid"], p.info["name"] or "?", p.info["username"] or ""))
            except Exception:
                continue
        rows.sort(reverse=True)
        out = [f"{'PID':>7}  {'MEM(MB)':>8}  {'USER':<20} NAME"]
        for mem, pid, name, user in rows[:n]:
            out.append(f"{pid:>7}  {mem:>8.1f}  {user[:20]:<20} {name}")
        return "\n".join(out)

    def _find(self, args: List[str]) -> str:
        if psutil is None:
            return "psutil not installed"
        if not args:
            return "usage: find <name>"
        q = args[0].lower()
        hits = []
        for p in psutil.process_iter(["pid", "name"]):
            try:
                if q in (p.info["name"] or "").lower():
                    hits.append(f"  pid {p.info['pid']:>7}  {p.info['name']}")
            except Exception:
                continue
        return "\n".join(hits) if hits else f"no process matching '{args[0]}'"

    def _kill(self, args: List[str]) -> str:
        p = self._proc(args)
        name = p.name()
        p.terminate()
        self._audit(f"Console: terminated {name} (pid {p.pid})", Severity.HIGH)
        return f"Terminated {name} (pid {p.pid})."

    def _suspend(self, args: List[str]) -> str:
        p = self._proc(args)
        p.suspend()
        self._audit(f"Console: suspended {p.name()} (pid {p.pid})", Severity.HIGH)
        return f"Suspended pid {p.pid} ({p.name()}). Use 'resume {p.pid}' to unfreeze."

    def _resume(self, args: List[str]) -> str:
        p = self._proc(args)
        p.resume()
        self._audit(f"Console: resumed {p.name()} (pid {p.pid})", Severity.MEDIUM)
        return f"Resumed pid {p.pid} ({p.name()})."

    def _prio(self, args: List[str]) -> str:
        if len(args) < 2:
            return "usage: prio <pid> <low|normal|high>"
        p = self._proc(args)
        level = args[1].lower()
        classes = {
            "low": getattr(psutil, "IDLE_PRIORITY_CLASS", 64),
            "normal": getattr(psutil, "NORMAL_PRIORITY_CLASS", 32),
            "high": getattr(psutil, "HIGH_PRIORITY_CLASS", 128),
        }
        if level not in classes:
            return "level must be low, normal, or high"
        p.nice(classes[level])
        self._audit(f"Console: set {p.name()} (pid {p.pid}) priority {level}", Severity.LOW)
        return f"Set pid {p.pid} priority to {level}."

    def _conns(self, args: List[str]) -> str:
        if psutil is None:
            return "psutil not installed"
        pid = int(args[0]) if args and args[0].isdigit() else None
        out = [f"{'PID':>7}  {'STATUS':<12} {'LOCAL':<24} REMOTE"]
        for c in psutil.net_connections(kind="inet"):
            if pid is not None and c.pid != pid:
                continue
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            out.append(f"{str(c.pid or '-'):>7}  {c.status:<12} {laddr:<24} {raddr}")
        return "\n".join(out) if len(out) > 1 else "no matching connections"

    def _tree(self, args: List[str]) -> str:
        p = self._proc(args)
        lines = [f"{p.name()} (pid {p.pid})"]
        try:
            for ch in p.children(recursive=True):
                lines.append(f"  └─ {ch.name()} (pid {ch.pid})")
        except Exception:
            pass
        return "\n".join(lines)

    # ── Module control ───────────────────────────────────────────────────────
    def _modules(self, args: List[str]) -> str:
        out = []
        for name, m in sorted(self.manager.modules.items()):
            flag = "on " if self.manager.is_enabled(name) else "off"
            out.append(f"  [{flag}] {m.status:<8} {m.name}")
        return "\n".join(out)

    def _module(self, args: List[str]) -> str:
        if len(args) < 2:
            return "usage: module <name> <on|off|restart>"
        # name may contain spaces; everything but the last token is the name
        action = args[-1].lower()
        query = " ".join(args[:-1]).lower()
        match = next((n for n in self.manager.modules if query in n.lower()), None)
        if not match:
            return f"no module matching '{query}'"
        if action == "on":
            self.manager.set_enabled(match, True); return f"{match}: enabled"
        if action == "off":
            self.manager.set_enabled(match, False); return f"{match}: disabled"
        if action == "restart":
            mod = self.manager.modules[match]; mod.stop(); mod.start(); return f"{match}: restarted"
        return "action must be on, off, or restart"

    def _test(self, args: List[str]) -> str:
        from angerona.core.selftest import SelfTestRunner
        names = None
        if args:
            q = " ".join(args).lower()
            if q != "all":
                names = [n for n in self.manager.modules if q in n.lower()]
                if not names:
                    return f"no module matching '{q}'"
        return SelfTestRunner(self.manager, self.bus).run(names)

    # ── Shark Attack After-Action Report ─────────────────────────────────────
    def _aar(self, args: List[str]) -> str:
        """Re-evaluate the last Shark Attack run against the flight-recorder
        ledger right now — no need to launch another drill, and no settle
        delay (useful for checking back later, e.g. after YARA's next
        5-minute scan cycle has had a chance to catch a file-drop step)."""
        from angerona.shark.aar_report import generate_aar
        return generate_aar(self.config.data_dir, settle_seconds=0)

    # ── Cyber Security Academy ────────────────────────────────────────────
    def _instructor_lazy(self):
        if self._instructor is None:
            from angerona.academy.security_academy import FlightInstructor
            self._instructor = FlightInstructor(self.config)
        return self._instructor

    def _achievements_lazy(self):
        if self._achievements is None:
            from angerona.academy.achievements import AchievementTracker
            self._achievements = AchievementTracker(self.config.data_dir)
        return self._achievements

    def _academy(self, args: List[str]) -> str:
        if not args:
            return ("usage: academy <explain|stages|style|coach|achievements|profile|tune> ...\n"
                    "type 'help' for the full academy command reference")
        sub, rest = args[0].lower(), args[1:]

        if sub == "stages":
            from angerona.academy.explainer_dictionary import all_stages
            return "\n".join(f"  {s}" for s in all_stages())

        if sub == "explain":
            if not rest:
                return "usage: academy explain <stage>  (see: academy stages)"
            from angerona.academy.explainer_dictionary import explain
            fi = self._instructor_lazy()
            return explain(" ".join(rest), style=fi.style.value)

        if sub == "style":
            if not rest:
                fi = self._instructor_lazy()
                return f"current style: {fi.style.value}  (usage: academy style <technical|analogy>)"
            try:
                self._instructor_lazy().set_style(rest[0])
            except ValueError as exc:
                return str(exc)
            return f"Flight Instructor style set to '{rest[0].lower()}'."

        if sub == "coach":
            import json
            path = Path(self.config.data_dir) / "shark_aar.json"
            if not path.exists():
                return "No shark_aar.json yet — run 'aar' (or a Shark Attack drill) first."
            try:
                verdicts = json.loads(path.read_text(encoding="utf-8")).get("verdicts", [])
            except Exception as exc:
                return f"could not read shark_aar.json: {exc}"
            blocks = self._instructor_lazy().coach_post_mortem(verdicts)
            # Only award for an actual genuine detection miss — Discovery
            # (no detector by design) and Noise Injection staying quiet (its
            # PASS state) both leave caught=False on every single drill, so
            # gating on "any(not caught)" without the category filter would
            # award this on nearly every run, not just real blind spots.
            had_real_miss = any(
                v.get("category", "detection") == "detection" and not v.get("caught")
                for v in verdicts)
            if had_real_miss:
                got = self._achievements_lazy().award_manual("blind_spot_finder")
                if got:
                    blocks.append(f"\n\U0001F393 Achievement unlocked: {got.icon} {got.title} — {got.description}")
            return "\n\n".join(blocks)

        if sub == "achievements":
            return self._achievements_lazy().summary()

        if sub == "profile":
            from angerona.academy.profiler import PerformanceProfiler
            return PerformanceProfiler().render_line()

        if sub == "tune":
            from angerona.academy.profiler import TuningSandbox
            sandbox = TuningSandbox()
            if not rest:
                return sandbox.render(self.manager)
            if len(rest) < 2:
                return "usage: academy tune <KEY> <VALUE>   (no args to just list current values)"
            key, value = rest[0], rest[1]
            try:
                sandbox.set_value(key, value)
            except (KeyError, ValueError) as exc:
                return str(exc)
            return f"{key} = {value}"

        return f"unknown academy subcommand '{sub}' — see: help"

    # ── SQL threat hunting (osquery-style, read-only) ────────────────────────
    # ── Analyst-standard commands ────────────────────────────────────────────
    def _sessions(self, args: List[str]) -> str:
        import getpass
        lines = [f"current user: {getpass.getuser()}"]
        if psutil is not None:
            try:
                for u in psutil.users():
                    when = (time.strftime("%Y-%m-%d %H:%M", time.localtime(u.started))
                            if getattr(u, "started", None) else "?")
                    lines.append(f"  {u.name}  terminal={getattr(u, 'terminal', '') or '-'}  "
                                 f"host={getattr(u, 'host', '') or '-'}  since {when}")
            except Exception as exc:
                lines.append(f"  (sessions unavailable: {exc})")
        return "\n".join(lines)

    def _timeline(self, args: List[str]) -> str:
        n = int(args[0]) if args and args[0].isdigit() else 20
        evs = sorted(self.bus.recent(400), key=lambda e: e.ts)[-n:]
        if not evs:
            return "no recent events."
        return "\n".join(f"{e.time_str}  [{e.severity.label:8}] {e.module}: {e.message}"
                         for e in evs)

    def _iocs(self, args: List[str]) -> str:
        evs = [e for e in self.bus.recent(400)
               if e.severity >= Severity.HIGH
               and e.module not in ("Self-Test", "Status", "Console")]
        if not evs:
            return "no HIGH/CRITICAL indicators in recent history."
        out = [f"{len(evs)} indicator(s) at HIGH+ severity (newest first):"]
        for e in sorted(evs, key=lambda e: e.ts, reverse=True)[:30]:
            d = e.details or {}
            extra = "".join(f"  {k}={d[k]}" for k in ("path", "pid", "mitre", "driver") if d.get(k))
            out.append(f"  {e.time_str} [{e.severity.label}] {e.module}: {e.message}{extra}")
        return "\n".join(out)

    def _search(self, args: List[str]) -> str:
        if not args:
            return "usage: search <term>"
        term = " ".join(args).lower()
        hits = [e for e in self.bus.recent(600)
                if term in (e.message or "").lower() or term in e.module.lower()]
        if not hits:
            return f"no recent events matching '{term}'."
        return "\n".join(f"{e.time_str} [{e.severity.label}] {e.module}: {e.message}"
                         for e in sorted(hits, key=lambda e: e.ts)[-40:])

    def _hashes(self, args: List[str]) -> str:
        if not args:
            return "usage: hashes <pid|path>   (SHA-256 of a process image or a file)"
        target = args[0]
        if target.isdigit() and psutil is not None:
            try:
                path = psutil.Process(int(target)).exe()
            except Exception as exc:
                return f"pid {target}: {exc}"
        else:
            path = target
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return f"{path}\n  size:   {os.path.getsize(path)} bytes\n  sha256: {h.hexdigest()}"
        except Exception as exc:
            return f"hash failed for {path}: {exc}"

    def _uptime(self, args: List[str]) -> str:
        out = []
        if psutil is not None:
            try:
                boot = psutil.boot_time()
                out.append(f"host up since {time.strftime('%Y-%m-%d %H:%M', time.localtime(boot))} "
                           f"(~{int((time.time() - boot) // 3600)}h)")
                p = psutil.Process(os.getpid())
                out.append(f"angerona up ~{int((time.time() - p.create_time()) // 60)} min "
                           f"(pid {os.getpid()})")
            except Exception as exc:
                out.append(f"(uptime unavailable: {exc})")
        return "\n".join(out) or "unavailable"

    def _env(self, args: List[str]) -> str:
        c = self.config
        return (f"ollama host : {getattr(c, 'ollama_host', '?')}\n"
                f"ollama model: {getattr(c, 'ollama_model', '?')}\n"
                f"data dir    : {getattr(c, 'data_dir', '?')}\n"
                f"theme       : {getattr(c, 'theme', '?')}\n"
                f"modules     : {len(self.manager.modules)} discovered")

    def _query(self, args: List[str]) -> str:
        if psutil is None:
            return "psutil not installed"
        sql = " ".join(args).strip()
        if not sql:
            return ("usage: query <SELECT ...>\n"
                    "tables: processes, connections, ports (read-only)")
        if not sql.lower().lstrip().startswith("select"):
            return "only SELECT queries are allowed (read-only threat hunting)"
        import sqlite3
        db = sqlite3.connect(":memory:")
        try:
            self._load_hunt_tables(db)
            cur = db.execute(sql)
            cols = [d[0] for d in cur.description]
            rows = cur.fetchmany(200)
        except Exception as exc:
            return f"query error: {exc}"
        finally:
            db.close()
        if not rows:
            return "(no rows)"
        out = ["  " + " | ".join(cols), "  " + "-" * 40]
        for r in rows:
            out.append("  " + " | ".join("" if x is None else str(x) for x in r))
        return "\n".join(out)

    def _load_hunt_tables(self, db) -> None:
        db.execute("CREATE TABLE processes (pid INT, name TEXT, exe TEXT, ppid INT, "
                   "username TEXT, mem_mb REAL)")
        for p in psutil.process_iter(["pid", "name", "exe", "ppid", "username", "memory_info"]):
            try:
                i = p.info
                mem = round(i["memory_info"].rss / (1024 * 1024), 1) if i.get("memory_info") else 0
                db.execute("INSERT INTO processes VALUES (?,?,?,?,?,?)",
                           (i["pid"], i.get("name"), i.get("exe"), i.get("ppid"),
                            i.get("username"), mem))
            except Exception:
                continue
        db.execute("CREATE TABLE connections (pid INT, status TEXT, laddr TEXT, raddr TEXT, "
                   "lport INT, rport INT)")
        db.execute("CREATE TABLE ports (pid INT, proto TEXT, laddr TEXT, lport INT)")
        for c in psutil.net_connections(kind="inet"):
            try:
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                lport = c.laddr.port if c.laddr else None
                rport = c.raddr.port if c.raddr else None
                db.execute("INSERT INTO connections VALUES (?,?,?,?,?,?)",
                           (c.pid, c.status, laddr, raddr, lport, rport))
                if c.status == "LISTEN":
                    proto = "tcp" if c.type == 1 else "udp"
                    db.execute("INSERT INTO ports VALUES (?,?,?,?)",
                               (c.pid, proto, laddr, lport))
            except Exception:
                continue
        db.commit()

    def _incidents(self, args: List[str]) -> str:
        from angerona.core.incidents import get_correlator
        n = int(args[0]) if args and args[0].isdigit() else 12
        return get_correlator().render(n)

    def _incident(self, args: List[str]) -> str:
        if not args:
            return "usage: incident <id-fragment>   (see: incidents)"
        from angerona.core.incidents import get_correlator
        return get_correlator().detail(" ".join(args))

    def _coverage(self, args: List[str]) -> str:
        from angerona.core import attack_coverage
        return attack_coverage.render()

    def _remlog(self, args: List[str]) -> str:
        """remlog [n|<T####>]  — show remediation action audit log."""
        from angerona.core.remediation_log import get_log
        import datetime
        rlog = get_log()
        if rlog is None:
            return "Remediation log not initialised (app not fully started)."

        mitre_filter = None
        n = 20
        for a in args:
            if a.upper().startswith("T") and a[1:].isdigit():
                mitre_filter = a.upper()
            elif a.isdigit():
                n = int(a)

        entries = rlog.by_mitre(mitre_filter, n) if mitre_filter else rlog.recent(n)
        if not entries:
            return "No remediation log entries" + (f" for {mitre_filter}" if mitre_filter else "") + "."

        _OUTCOME_ICON = {
            "applied":      "✔",
            "rolled_back":  "↩",
            "skipped":      "–",
            "dry_run":      "·",
            "error":        "✖",
        }
        stats = rlog.stats()
        header = (f"Remediation log — {stats.get('total', 0)} total  "
                  f"applied:{stats.get('applied', 0)}  "
                  f"skipped:{stats.get('skipped', 0)}  "
                  f"rolled_back:{stats.get('rolled_back', 0)}  "
                  f"errors:{stats.get('error', 0)}")
        sep = "─" * 72
        lines = [header, sep]
        for e in entries:
            ts = datetime.datetime.fromtimestamp(e["ts"]).strftime("%Y-%m-%d %H:%M:%S")
            icon = _OUTCOME_ICON.get(e["outcome"], "?")
            host = "[HOST]" if e["host_level"] else ""
            ver = ""
            if e["verified"] is True:
                ver = " verified✔"
            elif e["verified"] is False:
                ver = " verify✖"
            lines.append(
                f"{icon} {ts}  {e['mitre']:<10} {e['action_key']:<26} "
                f"{e['outcome']:<12}{host}{ver}  [{e['trigger']}]"
            )
        return "\n".join(lines)

    def _threat(self, args: List[str]) -> str:
        events = self.bus.recent(80)
        worst = max((e.severity for e in events), default=Severity.INFO)
        crit = sum(1 for e in events if e.severity == Severity.CRITICAL)
        running = sum(1 for m in self.manager.modules.values() if m.status == "running")
        return (f"Threat level: {worst.label}\n"
                f"Modules running: {running}/{len(self.manager.modules)}\n"
                f"Critical in recent window: {crit}")

    # ── Enterprise: Scheduled tasks ─────────────────
    def _schtasks(self, args):
        """List Windows scheduled tasks."""
        if os.name != "nt":
            return "schtasks: Windows only."
        try:
            import subprocess
            from angerona.core.win import check_output_hidden
            out = check_output_hidden(
                ["schtasks", "/query", "/fo", "csv", "/nh"],
                text=True, timeout=30, stderr=subprocess.DEVNULL,
            )
            rows = []
            for l in out.strip().splitlines():
                parts = l.strip('"').split('","')
                name = parts[0] if parts else ""
                status = parts[-1] if len(parts) >= 3 else ""
                if name and not name.startswith("\\Microsoft\\Windows"):
                    rows.append(f"{name:<55}  {status}")
            if not rows:
                return "No non-Microsoft scheduled tasks found."
            return f"{'Task Name':<55}  Status\n{'─'*70}\n" + "\n".join(rows[:60])
        except Exception as exc:
            return f"schtasks error: {exc}"

    def _services(self, args):
        """Enumerate Windows services."""
        filt = args[0].lower() if args else ""
        if psutil is None:
            return "services: psutil not available."
        try:
            rows = []
            for svc in psutil.win_service_iter():
                try:
                    name, status, start = svc.name(), svc.status(), svc.start_type()
                    if filt and filt not in name.lower():
                        continue
                    flag = "⚠" if (start == "automatic" and status != "running") else " "
                    rows.append(f"{flag} {name:<35} {status:<10} {start}")
                except Exception:
                    pass
            if not rows:
                return f"No services{' matching ' + repr(filt) if filt else ''}."
            return f"  {'Name':<35} {'State':<10} Start\n{'─'*65}\n" + "\n".join(rows[:80])
        except AttributeError:
            return "services: Windows only."
        except Exception as exc:
            return f"services error: {exc}"

    def _asn(self, args):
        """IP hostname + PTR lookup + bus event hits."""
        if not args:
            return "usage: asn <ip>"
        ip = args[0]
        import socket
        lines = [f"Target: {ip}"]
        try:
            host = socket.gethostbyaddr(ip)
            lines.append(f"Hostname:  {host[0]}")
        except Exception:
            lines.append("Hostname:  (no PTR record)")
        events = [e for e in self.bus.recent(200)
                  if ip in e.message or ip in str(e.details)]
        lines.append(f"Bus hits:  {len(events)} recent event(s) mentioning this IP")
        for e in events[:5]:
            ts = time.strftime("%H:%M:%S", time.localtime(e.ts))
            lines.append(f"  [{ts}] {e.severity.label}  {e.module}: {e.message[:80]}")
        return "\n".join(lines)

    def _lateral(self, args):
        """Lateral movement indicators from recent events."""
        lm_tags = {"T1021","T1076","T1570","T1560","T1135","T1078","T1550","T1563","T1534"}
        lm_kw = {"smb","rdp","admin$","ipc$","lateral","wmi","winrm",
                 "pass-the-hash","pass-the-ticket","psexec","logon failure","4624","4625","4648"}
        hits = [e for e in self.bus.recent(500)
                if (set(getattr(e,"mitre_tags",[]) or []) & lm_tags)
                or any(k in e.message.lower() for k in lm_kw)]
        if not hits:
            return "No lateral movement indicators in recent event window."
        lines = [f"Lateral movement signals ({len(hits)} events):"]
        for e in hits[:30]:
            ts = time.strftime("%H:%M:%S", time.localtime(e.ts))
            tags = ",".join(getattr(e,"mitre_tags",[]) or [])
            lines.append(f"  [{ts}] {e.severity.label:<8} {e.module:<12}  {tags:<10}  {e.message[:70]}")
        return "\n".join(lines)

    def _reg(self, args):
        """Registry query."""
        if os.name != "nt":
            return "reg: Windows only."
        if not args:
            return r"usage: reg HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
        key = " ".join(args)
        try:
            import subprocess
            from angerona.core.win import check_output_hidden
            out = check_output_hidden(["reg","query",key], text=True, timeout=15,
                                      stderr=subprocess.DEVNULL)
            lines = [l for l in out.strip().splitlines() if l.strip()]
            return "\n".join(lines[:60]) or "(empty key)"
        except Exception as exc:
            return f"reg error: {exc}"

    def _dump_strings(self, args):
        """Extract ASCII strings from a process's virtual memory."""
        if not args:
            return "usage: dump <pid>"
        if os.name != "nt":
            return "dump: Windows only."
        try:
            pid = int(args[0])
        except ValueError:
            return "usage: dump <pid>  (numeric PID)"
        try:
            import ctypes, re as _re
            from ctypes import wintypes
            k32 = ctypes.windll.kernel32
            handle = k32.OpenProcess(0x0010 | 0x0400, False, pid)
            if not handle:
                return f"dump: access denied to PID {pid} (need elevation?)"
            class _MBI(ctypes.Structure):
                _fields_ = [("BaseAddress",ctypes.c_void_p),("AllocationBase",ctypes.c_void_p),
                             ("AllocationProtect",ctypes.c_ulong),("RegionSize",ctypes.c_size_t),
                             ("State",ctypes.c_ulong),("Protect",ctypes.c_ulong),("Type",ctypes.c_ulong)]
            pat = _re.compile(rb"[ -~]{6,}")
            results = []
            addr = 0; mbi = _MBI(); read = 0; MAX = 32*1024*1024
            while k32.VirtualQueryEx(handle,ctypes.c_void_p(addr),ctypes.byref(mbi),ctypes.sizeof(mbi)) > 0:
                if mbi.State == 0x1000 and read < MAX:
                    sz = min(mbi.RegionSize, MAX-read)
                    buf = ctypes.create_string_buffer(sz); n = ctypes.c_size_t(0)
                    if k32.ReadProcessMemory(handle,mbi.BaseAddress,buf,sz,ctypes.byref(n)):
                        for m in pat.findall(buf.raw[:n.value]):
                            s = m.decode("ascii","ignore")
                            if s not in results: results.append(s)
                    read += mbi.RegionSize
                addr += mbi.RegionSize if mbi.RegionSize else 4096
                if addr > 0x7FFFFFFFFFFF: break
            k32.CloseHandle(handle)
            if not results:
                return f"dump: no readable strings in PID {pid}."
            interesting = [s for s in results if
                           _re.search(rb"https?://|\\[A-Za-z]|\.exe|\.dll|\.ps1|192\.|10\.|admin",
                                      s.encode())]
            out = [f"Strings dump for PID {pid} — {len(results)} unique ({len(interesting)} notable):"]
            out += [f"  {s}" for s in (interesting[:40] if interesting else results[:40])]
            return "\n".join(out)
        except Exception as exc:
            return f"dump error: {exc}"

    def _autoruns(self, args):
        """Check common persistence registry surfaces for suspicious entries."""
        if os.name != "nt":
            return "autoruns: Windows only."
        try:
            import winreg
        except ImportError:
            return "autoruns: winreg not available."
        SUSP = ("temp","appdata","public","tmp","\\users\\","cmd.exe","powershell",
                "wscript","cscript","mshta","regsvr32","rundll32","certutil",
                "bitsadmin","encoded","bypass","hidden",".vbs",".js",".ps1",".bat",".hta")
        hits = []
        keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
        ]
        for hive, subkey in keys:
            try:
                with winreg.OpenKey(hive, subkey) as k:
                    i = 0
                    while True:
                        try:
                            name, data, _ = winreg.EnumValue(k, i)
                            susp = any(kw in str(data).lower() for kw in SUSP)
                            hits.append((subkey.split("\\")[-1], name, str(data)[:80],
                                         "⚠ SUSPICIOUS" if susp else "  ok"))
                            i += 1
                        except OSError:
                            break
            except Exception:
                pass
        if not hits:
            return "autoruns: no entries found (need elevation for HKLM?)."
        lines = [f"{'Surface':<14}  {'Name':<30}  {'Value':<50}  Flag", "─"*100]
        for surface, name, val, flag in hits:
            lines.append(f"{surface:<14}  {name:<30}  {val:<50}  {flag}")
        return "\n".join(lines)

    def _portmap(self, args):
        """Map listening ports to process names."""
        if psutil is None:
            return "portmap: psutil not available."
        try:
            rows = []
            for c in psutil.net_connections(kind="all"):
                if not c.laddr:
                    continue
                is_listen = (getattr(c, "status", "") in ("LISTEN", ""))
                is_udp = (c.type and "DGRAM" in str(c.type))
                if not (is_listen or is_udp):
                    continue
                laddr = f"{c.laddr.ip}:{c.laddr.port}"
                proto = "UDP" if is_udp else "TCP"
                try:
                    pname = psutil.Process(c.pid).name() if c.pid else "—"
                except Exception:
                    pname = "—"
                rows.append((c.laddr.port, proto, laddr, pname, str(c.pid or "")))
            rows.sort(key=lambda r: r[0])
            if not rows:
                return "No listening sockets found."
            lines = [f"{'Bind':<32} {'Proto':<5} {'Process':<25} PID", "─"*70]
            for _, proto, laddr, pname, pid in rows[:60]:
                lines.append(f"{laddr:<32} {proto:<5} {pname:<25} {pid}")
            return "\n".join(lines)
        except Exception as exc:
            return f"portmap error: {exc}"

    # ── AI pass-through ─────────────────────────────────────────────────────
    def _ai(self, query: str) -> str:
        """Send a free-form query to the local Ollama AI."""
        import json
        import urllib.request
        host = getattr(self.config, "ollama_host", "http://localhost:11434")
        model = getattr(self.config, "ollama_model", "llama3")
        payload = json.dumps({"model": model, "prompt": query, "stream": False}).encode()
        try:
            req = urllib.request.Request(
                f"{host}/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
            return data.get("response", "").strip() or "(no response)"
        except Exception as exc:
            return f"AI unavailable: {exc}"

    def _ask_cmd(self, args: List[str]) -> str:
        """ask <query> — send a free-form question to the local AI."""
        if not args:
            return "usage: ask <your question>"
        return self._ai(" ".join(args))

