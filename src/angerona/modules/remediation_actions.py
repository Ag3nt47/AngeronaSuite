"""
remediation_actions.py — vetted, reversible active-remediation library.

Why this exists: the Posture Hardening loop used to *stage* an LLM-authored
PowerShell script and never run it (review-gated), so a red-team finding never
actually got fixed. Auto-running a 2B-model's freehand PowerShell is exactly the
poisoning / DoS vector called out in the threat assessment. The safe way to get
REAL active patching is a library of deterministic, idempotent, REVERSIBLE
actions the AI *selects from* (not authors), applied with a backup, a verify
step, and rollback-on-failure, behind an explicit opt-in.

Nothing here runs system-modifying actions unless a caller passes apply=True AND
(for host-level changes) the opt-in env ANGERONA_AUTO_REMEDIATE=1 is set. The
default is a dry-run PLAN so you can see exactly what would change first.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from angerona.core.win import run_hidden, NO_WINDOW

try:
    import psutil as _psutil
except Exception:
    _psutil = None

# Processes we never suspend/kill — destabilising Windows itself is not remediation.
_SYSTEM_NEVER_KILL: frozenset[str] = frozenset({
    "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "svchost.exe",
    "ntoskrnl.exe", "system", "registry",
})


def _auto_apply_enabled() -> bool:
    return os.environ.get("ANGERONA_AUTO_REMEDIATE", "0") == "1"


def _first_path_in(weakness: dict) -> str | None:
    """Best-effort extraction of a file path a weakness refers to."""
    for k in ("path", "artifact", "file"):
        if weakness.get(k):
            return str(weakness[k])
    msg = str(weakness.get("detect_message") or weakness.get("name") or "")
    for tok in msg.replace("\\", "/").split():
        if ("/" in tok or ":" in tok) and "." in tok:
            return tok.strip("'\"")
    return None


def _first_ip_in(weakness: dict) -> str | None:
    """Best-effort extraction of a routable remote IP a weakness refers to
    (the C2 / exfil peer). Loopback, unspecified, and link-local are ignored —
    we never firewall-block those."""
    import ipaddress
    import re
    cands = []
    for k in ("remote_ip", "raddr", "ip", "dst", "peer"):
        if weakness.get(k):
            cands.append(str(weakness[k]))
    blob = " ".join(str(weakness.get(k, "")) for k in
                    ("detect_message", "name", "message", "raddr"))
    cands += re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", blob)
    for c in cands:
        c = c.split(":")[0].strip()  # strip :port if present
        try:
            ip = ipaddress.ip_address(c)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_unspecified or ip.is_link_local:
            continue
        return str(ip)
    return None


class RemediationAction:
    key = "base"
    title = "base"
    reversible = True
    host_level = False        # True = changes the OS (registry/services); gated by opt-in

    def matches(self, weakness: dict) -> bool:
        return False

    def apply(self, weakness: dict, quarantine_dir: Path) -> dict:
        raise NotImplementedError

    def rollback(self, record: dict) -> dict:
        return {"ok": False, "error": "not reversible"}

    def verify(self, weakness: dict, record: dict) -> bool:
        # Every registered mutation must prove its own exact postcondition.
        # A permissive base implementation can turn a command failure into a
        # false PATCHED receipt, so unknown actions fail closed.
        return False


def _expected_process_identity(weakness: dict) -> dict | None:
    """Extract the sensor-bound process identity required for PID mutation."""
    try:
        pid = int(weakness.get("pid"))
        created = float(
            weakness.get("process_create_time")
            or weakness.get("pid_create_time")
            or weakness.get("create_time")
        )
    except (TypeError, ValueError):
        return None
    if pid <= 4 or pid in {os.getpid(), os.getppid()} or created <= 0:
        return None
    exe = str(
        weakness.get("exe")
        or weakness.get("process_path")
        or weakness.get("image")
        or ""
    ).strip()
    name = str(
        weakness.get("process_name")
        or weakness.get("proc_name")
        or weakness.get("name")
        or ""
    ).strip().casefold()
    if not exe and not name:
        return None
    return {
        "pid": pid,
        "create_time": created,
        "exe": os.path.normcase(os.path.abspath(exe)) if exe else "",
        "name": name,
    }


def _compare_process_identity(process, expected: dict) -> bool | None:
    """Return True/False for a proven match/mismatch, None when unreadable."""
    try:
        if int(process.pid) != int(expected["pid"]):
            return False
        if abs(float(process.create_time()) - float(expected["create_time"])) > 0.001:
            return False
        current_name = str(process.name() or "").casefold()
        if expected.get("name") and current_name != expected["name"]:
            return False
        if expected.get("exe"):
            current_exe = os.path.normcase(os.path.abspath(str(process.exe() or "")))
            if current_exe != expected["exe"]:
                return False
        return current_name not in _SYSTEM_NEVER_KILL
    except Exception:
        return None


def _process_matches_identity(process, expected: dict) -> bool:
    """Revalidate a retained psutil Process immediately before mutation."""
    return _compare_process_identity(process, expected) is True


def _no_such_process(exc: Exception) -> bool:
    cls = getattr(_psutil, "NoSuchProcess", ()) if _psutil is not None else ()
    return bool(cls) and isinstance(exc, cls)


# ── 1. Quarantine a flagged file (SAFE, reversible, no OS state) ─────────────
class QuarantineFileAction(RemediationAction):
    key = "quarantine_file"
    title = "Quarantine the flagged file"
    reversible = True
    host_level = False

    def matches(self, weakness: dict) -> bool:
        p = _first_path_in(weakness)
        return bool(p) and Path(p).is_file()

    def apply(self, weakness: dict, quarantine_dir: Path) -> dict:
        src = Path(_first_path_in(weakness))
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        dst = quarantine_dir / f"{int(time.time())}_{src.name}.quarantine"
        shutil.move(str(src), str(dst))
        return {"ok": True, "action": self.key, "original": str(src), "quarantined": str(dst)}

    def rollback(self, record: dict) -> dict:
        try:
            shutil.move(record["quarantined"], record["original"])
            return {"ok": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def verify(self, weakness: dict, record: dict) -> bool:
        return not Path(record["original"]).exists() and Path(record["quarantined"]).exists()


# ── 2. Disable a vulnerable driver's service (REAL, host-level, reversible) ──
class DisableDriverServiceAction(RemediationAction):
    key = "disable_driver_service"
    title = "Disable the vulnerable driver's service (BYOVD)"
    reversible = True
    host_level = True

    def _svc(self, weakness: dict) -> str | None:
        drv = weakness.get("driver") or ""
        if not drv:
            p = _first_path_in(weakness) or ""
            if p.lower().endswith(".sys"):
                drv = Path(p).name
        return Path(drv).stem or None if drv else None

    def matches(self, weakness: dict) -> bool:
        return os.name == "nt" and bool(self._svc(weakness))

    def apply(self, weakness: dict, quarantine_dir: Path) -> dict:
        del quarantine_dir
        svc = self._svc(weakness)
        prior = run_hidden(["sc", "qc", svc], capture_output=True, text=True, timeout=15)
        prior_text = str(prior.stdout or "")
        match = re.search(r"START_TYPE\s*:\s*([0-4])", prior_text, re.IGNORECASE)
        prior_modes = {"0": "boot", "1": "system", "2": "auto", "3": "demand", "4": "disabled"}
        if prior.returncode != 0 or match is None:
            return {
                "ok": False,
                "action": self.key,
                "service": svc,
                "error": "could not prove prior driver start mode",
                "rc": prior.returncode,
            }
        prior_mode = prior_modes[match.group(1)]
        changed = run_hidden(
            ["sc", "config", svc, "start=", "disabled"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return {
            "ok": changed.returncode == 0,
            "action": self.key,
            "service": svc,
            "prior_start": prior_mode,
            "prior_qc": prior_text[:400],
            "rc": changed.returncode,
            "stderr": str(changed.stderr or "")[:300],
        }

    def rollback(self, record: dict) -> dict:
        try:
            prior = record.get("prior_start")
            if prior not in {"boot", "system", "auto", "demand", "disabled"}:
                return {"ok": False, "error": "prior driver start mode is unavailable"}
            result = run_hidden(
                ["sc", "config", record["service"], "start=", prior],
                capture_output=True,
                text=True,
                timeout=15,
            )
            return {"ok": result.returncode == 0, "rc": result.returncode}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def verify(self, weakness: dict, record: dict) -> bool:
        del weakness
        if not record.get("ok"):
            return False
        try:
            result = run_hidden(
                ["sc", "qc", record["service"]],
                capture_output=True,
                text=True,
                timeout=15,
            )
            match = re.search(
                r"START_TYPE\s*:\s*([0-4])", str(result.stdout or ""), re.IGNORECASE
            )
            return result.returncode == 0 and match is not None and match.group(1) == "4"
        except Exception:
            return False


def _hay(weakness: dict) -> str:
    return " ".join(str(weakness.get(k, "")) for k in
                    ("mitre_id", "mitre", "name", "technique", "category",
                     "detect_message")).lower()


# ── 3. Registry hardening (REAL, host-level, reversible) ────────────────────
class RegistryHardeningAction(RemediationAction):
    key = "registry_hardening"
    title = "Apply a vetted registry hardening"
    reversible = True
    host_level = True

    # Vetted allow-list: (match substrings) -> (subkey, value_name, dword, why).
    # Model/logic only SELECTS from this table; it never authors registry paths.
    _TABLE = [
        (("t1003", "credential", "lsass", "mimikatz"),
         (r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", 1,
          "Run LSASS as a Protected Process (blocks credential dumping)")),
        (("wdigest", "t1003", "credential"),
         (r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
          "UseLogonCredential", 0, "Disable WDigest cleartext credential caching")),
        # T1562.011: Defense evasion — script-block logging disabled specifically
        # (NOT bare "t1562" — that MITRE ID also covers AMSI bypass, which must
        # route to DefenderHardeningAction, not this registry fix).
        (("t1562.011", "script block", "powershell logging", "scriptblock"),
         (r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
          "EnableScriptBlockLogging", 1, "Re-enable PowerShell script-block logging")),
        # T1055: Process injection — prohibit remote code execution via IFEO silent exits
        (("t1055", "process injection", "inject", "hollowing"),
         (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
          "MitigationOptions", 0x100, "Set process-injection mitigation flag")),
        # T1548: UAC bypass — re-assert UAC consent prompt for all apps
        (("t1548", "uac bypass", "bypassuac", "elevation"),
         (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
          "ConsentPromptBehaviorAdmin", 2,
          "Restore UAC to 'Prompt for consent on secure desktop'")),
        # T1547: Persistence via ASEP — ensure autorun is audit-logged
        (("t1547", "autorun", "persistence", "run key"),
         (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
          "NoDriveTypeAutoRun", 0xFF, "Disable autorun on all drive types")),
        # T1112: Registry modification — enable registry auditing via advanced audit
        (("t1112", "registry modification", "regmod"),
         (r"SYSTEM\CurrentControlSet\Control\Lsa", "auditbaseobjects", 1,
          "Enable base-object auditing for registry change detection")),
    ]

    def _entry(self, w: dict):
        h = _hay(w)
        return next((e for subs, e in self._TABLE if any(s in h for s in subs)), None)

    def matches(self, w: dict) -> bool:
        return os.name == "nt" and self._entry(w) is not None

    def apply(self, w: dict, quarantine_dir: Path) -> dict:
        import winreg
        subkey, name, value, why = self._entry(w)
        prior = None
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey, 0, winreg.KEY_READ)
            try:
                prior, _ = winreg.QueryValueEx(k, name)
            finally:
                winreg.CloseKey(k)
        except FileNotFoundError:
            prior = None
        k = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, subkey, 0, winreg.KEY_SET_VALUE)
        try:
            winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, int(value))
        finally:
            winreg.CloseKey(k)
        return {"ok": True, "action": self.key, "subkey": subkey, "name": name,
                "prior": prior, "new": int(value), "why": why}

    def rollback(self, record: dict) -> dict:
        import winreg
        try:
            k = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, record["subkey"], 0,
                                   winreg.KEY_SET_VALUE)
            try:
                if record.get("prior") is None:
                    try:
                        winreg.DeleteValue(k, record["name"])
                    except FileNotFoundError:
                        pass
                else:
                    winreg.SetValueEx(k, record["name"], 0, winreg.REG_DWORD, int(record["prior"]))
            finally:
                winreg.CloseKey(k)
            return {"ok": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def verify(self, w: dict, record: dict) -> bool:
        import winreg
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, record["subkey"], 0, winreg.KEY_READ)
            try:
                val, _ = winreg.QueryValueEx(k, record["name"])
            finally:
                winreg.CloseKey(k)
            return int(val) == int(record["new"])
        except Exception:
            return False


# ── 4. ACL lockdown of a flagged staging directory (REAL, reversible) ───────
class LockdownAclAction(RemediationAction):
    key = "lockdown_acl"
    title = "Lock down a flagged directory's ACL"
    reversible = True
    host_level = True

    def _dir(self, w: dict):
        p = _first_path_in(w)
        return p if p and Path(p).is_dir() else None

    def matches(self, w: dict) -> bool:
        return os.name == "nt" and self._dir(w) is not None

    def apply(self, w: dict, quarantine_dir: Path) -> dict:
        target = self._dir(w)
        Path(quarantine_dir).mkdir(parents=True, exist_ok=True)
        backup = str(Path(quarantine_dir) / f"acl_{int(time.time())}.bak")
        parent = str(Path(target).parent)
        saved = run_hidden(
            ["icacls", target, "/save", backup, "/t"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if saved.returncode != 0 or not Path(backup).exists():
            return {
                "ok": False,
                "action": self.key,
                "target": target,
                "error": "ACL backup could not be verified",
                "rc": saved.returncode,
            }
        changed = run_hidden(
            [
                "icacls", target, "/inheritance:r", "/grant:r", "SYSTEM:(OI)(CI)F",
                f"{os.getenv('USERNAME', 'Administrators')}:(OI)(CI)F", "/t",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return {
            "ok": changed.returncode == 0,
            "action": self.key,
            "target": target,
            "acl_backup": backup,
            "parent": parent,
            "rc": changed.returncode,
        }

    def rollback(self, record: dict) -> dict:
        try:
            result = run_hidden(
                ["icacls", record["parent"], "/restore", record["acl_backup"]],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return {"ok": result.returncode == 0, "rc": result.returncode}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}


# ── 5. Re-assert the Windows Defender baseline (REAL; not undo-able) ─────────
class DefenderHardeningAction(RemediationAction):
    key = "defender_hardening"
    title = "Re-assert Windows Defender baseline (real-time + cloud)"
    reversible = False        # turning protection back ON is not something to revert
    host_level = True

    def matches(self, w: dict) -> bool:
        h = _hay(w)
        return os.name == "nt" and any(s in h for s in
                                       ("defense-evasion", "defender", "t1562", "amsi", "realtime"))

    def apply(self, w: dict, quarantine_dir: Path) -> dict:
        ps = ("Set-MpPreference -DisableRealtimeMonitoring $false -MAPSReporting Advanced "
              "-SubmitSamplesConsent SendAllSamples -ErrorAction SilentlyContinue")
        r = run_hidden(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
                       capture_output=True, text=True, timeout=30)
        return {"ok": r.returncode == 0, "action": self.key, "rc": r.returncode,
                "stderr": (r.stderr or "")[:300]}

    def verify(self, w: dict, record: dict) -> bool:
        try:
            r = run_hidden(["powershell", "-NoProfile", "-Command",
                            "(Get-MpPreference).DisableRealtimeMonitoring"],
                           capture_output=True, text=True, timeout=20)
            return "False" in (r.stdout or "")
        except Exception:
            return False


# ── 6. Network isolation — block a malicious remote IP (REAL, reversible) ────
class NetworkIsolationAction(RemediationAction):
    key = "network_isolation"
    title = "Block a malicious remote IP at the host firewall"
    reversible = True
    host_level = True

    def matches(self, w: dict) -> bool:
        return os.name == "nt" and _first_ip_in(w) is not None

    def apply(self, w: dict, quarantine_dir: Path) -> dict:
        del quarantine_dir
        ip = _first_ip_in(w)
        rule = f"Angerona-Block-{ip}-{time.time_ns()}"
        # Outbound + inbound block scoped to this one remote IP. Fully reversible
        # (delete the named rule). netsh is deterministic — nothing model-authored.
        rules: dict[str, str] = {}
        results: dict[str, int] = {}
        for direction in ("out", "in"):
            named = f"{rule}-{direction}"
            result = run_hidden(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={named}", f"dir={direction}", "action=block",
                    f"remoteip={ip}", "enable=yes",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            rules[direction] = named
            results[direction] = result.returncode
        return {
            "ok": all(code == 0 for code in results.values()) and len(results) == 2,
            "action": self.key,
            "ip": ip,
            "rule": rule,
            "rules": rules,
            "returncodes": results,
        }

    def rollback(self, record: dict) -> dict:
        try:
            rules = record.get("rules") or {
                "legacy": record.get("rule", "")
            }
            results = []
            for name in rules.values():
                if not name:
                    continue
                result = run_hidden(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                results.append(result.returncode)
            return {"ok": bool(results) and all(code == 0 for code in results), "returncodes": results}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def verify(self, w: dict, record: dict) -> bool:
        del w
        if not record.get("ok") or set(record.get("rules") or {}) != {"in", "out"}:
            return False
        try:
            for direction, name in record["rules"].items():
                result = run_hidden(
                    ["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}", "verbose"],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                output = str(result.stdout or "").casefold()
                wanted = "in" if direction == "in" else "out"
                if (
                    result.returncode != 0
                    or name.casefold() not in output
                    or record["ip"].casefold() not in output
                    or not re.search(rf"direction\s*:\s*{wanted}(?:bound)?\b", output)
                ):
                    return False
            return True
        except Exception:
            return False


# ── 7. AV-telemetry-aware file quarantine (G2-G) ────────────────────────────
class AVDetectionQuarantineAction(RemediationAction):
    """Quarantine a file identified by Windows Defender (av_telemetry_bridge).

    Matches weakness dicts that carry a 'threat_name' field (emitted by
    AVTelemetryBridgeModule for EID 1116/1117).  Delegates the actual file move
    to the same logic as QuarantineFileAction but records the threat name in the
    audit record for SIEM correlation.
    """
    key = "av_quarantine"
    title = "Quarantine file flagged by Windows Defender"
    reversible = True
    host_level = False

    def matches(self, weakness: dict) -> bool:
        if not weakness.get("threat_name"):
            return False
        p = _first_path_in(weakness)
        return bool(p) and Path(p).is_file()

    def apply(self, weakness: dict, quarantine_dir: Path) -> dict:
        src = Path(_first_path_in(weakness))
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        dst = quarantine_dir / f"{int(time.time())}_{src.name}.av_quarantine"
        shutil.move(str(src), str(dst))
        return {
            "ok":           True,
            "action":       self.key,
            "original":     str(src),
            "quarantined":  str(dst),
            "threat_name":  weakness.get("threat_name", ""),
            "av_severity":  weakness.get("av_severity", ""),
        }

    def rollback(self, record: dict) -> dict:
        try:
            shutil.move(record["quarantined"], record["original"])
            return {"ok": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def verify(self, weakness: dict, record: dict) -> bool:
        return (
            not Path(record["original"]).exists()
            and Path(record["quarantined"]).exists()
        )


# ── 8. Suspend a suspicious process (REAL, reversible, requires psutil) ──────
class SuspendProcessAction(RemediationAction):
    """Suspend (freeze) the offending process without killing it — preserves memory
    for forensics.  Reversible: rollback resumes the process.  Skipped for any
    process in the System32 never-kill list."""
    key = "suspend_process"
    title = "Suspend the suspicious process (reversible)"
    reversible = True
    host_level = True

    def _pid(self, w: dict) -> int | None:
        v = w.get("pid")
        try:
            return int(v) if v is not None else None
        except (TypeError, ValueError):
            return None

    def matches(self, w: dict) -> bool:
        expected = _expected_process_identity(w)
        if _psutil is None or expected is None:
            return False
        try:
            return _process_matches_identity(_psutil.Process(expected["pid"]), expected)
        except Exception:
            return False

    def apply(self, w: dict, quarantine_dir: Path) -> dict:
        del quarantine_dir
        expected = _expected_process_identity(w)
        pid = expected["pid"] if expected else self._pid(w)
        try:
            if expected is None:
                raise ValueError("sensor-bound PID identity is required")
            proc = _psutil.Process(pid)
            if not _process_matches_identity(proc, expected):
                raise RuntimeError("process identity changed before suspend")
            name = proc.name()
            proc.suspend()
            return {"ok": True, "action": self.key, **expected, "name": name.casefold()}
        except Exception as exc:
            return {"ok": False, "action": self.key, "pid": pid, "error": str(exc)}

    def rollback(self, record: dict) -> dict:
        try:
            process = _psutil.Process(record["pid"])
            if not _process_matches_identity(process, record):
                return {"ok": False, "error": "process identity changed before resume"}
            process.resume()
            return {"ok": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def verify(self, w: dict, record: dict) -> bool:
        if not record.get("ok"):
            return False
        try:
            process = _psutil.Process(record["pid"])
            return _process_matches_identity(process, record) and process.status() == "stopped"
        except Exception:
            return False


# ── 9. Kill a process (CRITICAL/ransomware only — irreversible) ───────────────
class KillProcessAction(RemediationAction):
    """Hard-terminate the process.  Used when suspension alone is insufficient
    (active ransomware, worm, credential harvester actively exfiltrating).
    Only matches when mitre/technique context strongly indicates active malware."""
    key = "kill_process"
    title = "Terminate the malicious process (hard-kill)"
    reversible = False
    host_level = True

    _TRIGGERS = ("ransomware", "t1486", "worm", "t1041", "t1210",
                 "cryptominer", "keylogger", "exfil")

    def _pid(self, w: dict) -> int | None:
        v = w.get("pid")
        try:
            return int(v) if v is not None else None
        except (TypeError, ValueError):
            return None

    def matches(self, w: dict) -> bool:
        expected = _expected_process_identity(w)
        if _psutil is None or expected is None:
            return False
        try:
            if not _process_matches_identity(_psutil.Process(expected["pid"]), expected):
                return False
        except Exception:
            return False
        h = _hay(w)
        return any(t in h for t in self._TRIGGERS)

    def apply(self, w: dict, quarantine_dir: Path) -> dict:
        del quarantine_dir
        expected = _expected_process_identity(w)
        pid = expected["pid"] if expected else self._pid(w)
        try:
            if expected is None:
                raise ValueError("sensor-bound PID identity is required")
            proc = _psutil.Process(pid)
            if not _process_matches_identity(proc, expected):
                raise RuntimeError("process identity changed before termination")
            name = proc.name()
            proc.kill()
            return {"ok": True, "action": self.key, **expected, "name": name.casefold()}
        except Exception as exc:
            return {"ok": False, "action": self.key, "pid": pid, "error": str(exc)}

    def verify(self, w: dict, record: dict) -> bool:
        if not record.get("ok"):
            return False
        try:
            process = _psutil.Process(record["pid"])
            # A reused PID is not proof that our target survived. The original
            # identity is gone, so only a proven mismatch is a success. An
            # AccessDenied/read error is unknown and therefore fails closed.
            return _compare_process_identity(process, record) is False
        except Exception as exc:
            return _no_such_process(exc)


# ── 10. Persistence cleanup — remove a Run/RunOnce entry (reversible) ────────
class PersistenceCleanupAction(RemediationAction):
    """Compatibility stub for legacy ambiguous autorun findings.

    A value name alone cannot authorize registry mutation: hive, 32/64-bit
    view, full subkey, registry type, and an expected data digest are all part
    of identity. Until the response catalog carries that typed evidence and a
    quarantined rollback export, autorun cleanup remains manual-review only.
    """
    key = "persistence_cleanup"
    title = "Remove malicious startup persistence entry (Run/RunOnce)"
    reversible = True
    host_level = True

    _RUN_KEYS = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    ]

    def _entry(self, w: dict):
        name = w.get("run_key_value") or w.get("persistence_entry")
        if not name:
            return None, None
        h = _hay(w)
        for trigger in ("t1547", "persistence", "run key", "autorun", "startup"):
            if trigger in h:
                return name, self._RUN_KEYS[0]
        return None, None

    def matches(self, w: dict) -> bool:
        del w
        return False

    def apply(self, w: dict, quarantine_dir: Path) -> dict:
        del w, quarantine_dir
        return {
            "ok": False,
            "action": self.key,
            "proposal_only": True,
            "error": (
                "Automatic autorun deletion is disabled: require typed hive/view/subkey/name/"
                "type/data-digest identity and a verified rollback export."
            ),
        }

    def rollback(self, record: dict) -> dict:
        del record
        return {"ok": False, "proposal_only": True}

    def verify(self, w: dict, record: dict) -> bool:
        del w, record
        return False


# ── registry of vetted actions (most specific first) ────────────────────────
ACTIONS: list[RemediationAction] = [
    KillProcessAction(),             # active ransomware/worm/exfil PID → hard-kill
    SuspendProcessAction(),          # suspicious PID → suspend (preserves forensics)
    # Ambiguous Run/RunOnce value-name deletion is deliberately not registered.
    DisableDriverServiceAction(),    # BYOVD driver → disable its service
    RegistryHardeningAction(),       # credential-access / UAC bypass → registry fix
    DefenderHardeningAction(),       # defense-evasion → re-assert Defender baseline
    NetworkIsolationAction(),        # C2 / exfil peer IP → host-firewall block
    # ACL lockdown stays proposal-only until a locale-independent descriptor
    # verifier can prove and restore the exact DACL, owner, and inheritance.
    AVDetectionQuarantineAction(),   # G2-G: AV telemetry threat → quarantine
    QuarantineFileAction(),          # flagged FILE → quarantine (fallback)
]


def select_action(weakness: dict) -> RemediationAction | None:
    """Deterministically map a weakness to the first vetted action that fits."""
    return next((a for a in ACTIONS if a.matches(weakness)), None)


def plan_remediation(weaknesses: list[dict]) -> list[dict]:
    """Dry-run: what WOULD be done, per weakness. No changes."""
    plan = []
    for w in weaknesses:
        a = select_action(w)
        plan.append({"mitre": w.get("mitre_id") or w.get("mitre"),
                     "action": a.key if a else None,
                     "title": a.title if a else "no vetted action — manual review"})
    return plan


def apply_remediation(weaknesses: list[dict], quarantine_dir, apply: bool = False,
                      allow_host: bool | None = None, log=None,
                      trigger: str = "", db_path=None) -> dict:
    """Apply vetted actions. Safe by default:
      * apply=False  → dry-run plan only (no changes).
      * apply=True   → applies non-host actions (e.g. quarantine).
      * host-level actions (registry/services) additionally require allow_host
        (defaults to the ANGERONA_AUTO_REMEDIATE opt-in). Every applied action is
        verified; a failed verify triggers an automatic rollback.
      * trigger — caller label written to the remediation_log (e.g. "PostureHardening")
      * db_path — if provided, inits the remediation_log singleton on first call
    Returns {'applied','skipped','records'} — records support later rollback."""
    if allow_host is None:
        allow_host = _auto_apply_enabled()
    qdir = Path(quarantine_dir)
    records, applied, skipped = [], 0, 0

    # ── audit log (init on first call if db_path supplied) ───────────────────
    try:
        from angerona.core.remediation_log import get_log, init_log
        if db_path is not None:
            _rlog = init_log(db_path)
        else:
            _rlog = get_log()
    except Exception:
        _rlog = None

    def _log(level, msg):
        if log:
            try:
                log(level, msg)
            except Exception:
                pass

    def _audit(mitre, action, outcome, verified=-1, rec=None):
        if _rlog is not None:
            try:
                return _rlog.log(
                    trigger=trigger or "remediation_actions",
                    mitre=mitre or "-",
                    action_key=action.key if action else "none",
                    action_title=action.title if action else "no vetted action",
                    outcome=outcome,
                    verified=verified,
                    host_level=action.host_level if action else False,
                    record=rec,
                )
            except Exception:
                pass
        return None

    for w in weaknesses:
        mitre = w.get("mitre_id") or w.get("mitre") or "-"
        action = select_action(w)
        if action is None:
            skipped += 1
            _audit(mitre, None, "skipped")
            continue
        if not apply:
            _log("INFO", f"PLAN {action.key} for {mitre}")
            _audit(mitre, action, "dry_run")
            continue
        if action.host_level and not allow_host:
            _log("INFO", f"SKIP host-level {action.key} (set ANGERONA_AUTO_REMEDIATE=1 to allow)")
            skipped += 1
            _audit(mitre, action, "skipped")
            continue
        try:
            rec = action.apply(w, qdir)
            rec["mitre"] = mitre
            ok = action.verify(w, rec)
            rec["verified"] = ok
            if not ok:
                rb = action.rollback(rec)
                rec["rolled_back"] = rb.get("ok")
                _log("CRITICAL", f"{action.key} FAILED verify — rolled back: {rec}")
                proof = _audit(
                    mitre, action, "rolled_back", verified=0, rec=rec
                )
                if proof:
                    rec["proof_receipt"] = proof
                skipped += 1
            else:
                applied += 1
                _log("INFO", f"APPLIED {action.key}: {rec}")
                proof = _audit(mitre, action, "applied", verified=1, rec=rec)
                if proof:
                    rec["proof_receipt"] = proof
                records.append(rec)
        except Exception as exc:
            skipped += 1
            _log("CRITICAL", f"{action.key} errored: {exc}")
            _audit(mitre, action, "error", rec={"error": str(exc)})
    return {"applied": applied, "skipped": skipped, "records": records}
