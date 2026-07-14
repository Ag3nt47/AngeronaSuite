"""core/sigma_engine.py — a minimal Sigma detection-rule engine.

Sigma is the community standard for portable detection rules. Supporting a Sigma
SUBSET lets Angerona import the huge public rule library and evaluate rules
against its own events — hundreds of detections for "free", standards-native.

This is an MVP matcher (not the full spec): it supports a `detection:` block of
named selection maps with field modifiers `contains`/`startswith`/`endswith`/`re`,
list values (OR), and a `condition` of the form `sel`, `sel1 and sel2`,
`sel1 or sel2`, `all of them`, `1 of them` (optionally with `and not filter`).
Events are matched against a flattened field dict (module, message, + details).

Pure/local. YAML loading uses PyYAML if present; rules can also be passed as dicts.
"""
from __future__ import annotations

import re


def load_rules(text: str) -> list[dict]:
    """Parse one or more Sigma YAML documents into rule dicts (needs PyYAML).
    Returns [] if PyYAML is unavailable or parsing fails."""
    try:
        import yaml  # type: ignore
    except Exception:
        return []
    try:
        return [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    except Exception:
        return []


def event_fields(event) -> dict:
    """Flatten an Angerona event into a Sigma-matchable field dict."""
    det = getattr(event, "details", None)
    fields = {"module": getattr(event, "module", ""),
              "message": getattr(event, "message", ""),
              "severity": getattr(getattr(event, "severity", None), "name", "")}
    if isinstance(det, dict):
        for k, v in det.items():
            fields[str(k)] = v
    return {k: v for k, v in fields.items()}


def _match_value(field_val, expected, modifier: str | None) -> bool:
    fv = "" if field_val is None else str(field_val)
    ev = "" if expected is None else str(expected)
    if modifier == "contains":
        return ev.lower() in fv.lower()
    if modifier == "startswith":
        return fv.lower().startswith(ev.lower())
    if modifier == "endswith":
        return fv.lower().endswith(ev.lower())
    if modifier == "re":
        try:
            return re.search(ev, fv, re.IGNORECASE) is not None
        except Exception:
            return False
    return fv.lower() == ev.lower()


def _match_selection(sel, fields: dict) -> bool:
    """A selection is a dict of {field[|modifier]: value|[values]} — AND across
    keys, OR across a key's list of values."""
    if isinstance(sel, list):   # list of maps → OR
        return any(_match_selection(s, fields) for s in sel)
    if not isinstance(sel, dict):
        return False
    for key, expected in sel.items():
        field, _, modifier = key.partition("|")
        fv = fields.get(field)
        vals = expected if isinstance(expected, list) else [expected]
        if not any(_match_value(fv, v, modifier or None) for v in vals):
            return False
    return True


def match(rule: dict, event) -> bool:
    """True if *event* matches the Sigma *rule*. Best-effort, never raises."""
    try:
        det = rule.get("detection") or {}
        if not isinstance(det, dict):
            return False
        condition = str(det.get("condition", "")).strip().lower()
        sels = {k: v for k, v in det.items() if k != "condition"}
        fields = event_fields(event)
        results = {name: _match_selection(sel, fields) for name, sel in sels.items()}

        # handle "... and not <filter>"
        negate = None
        if " and not " in condition:
            condition, _, neg = condition.partition(" and not ")
            negate = neg.strip()
        base = _eval_condition(condition.strip(), results, sels)
        if negate is not None:
            base = base and not results.get(negate, False)
        return base
    except Exception:
        return False


def _eval_condition(cond: str, results: dict, sels: dict) -> bool:
    if not cond:
        return any(results.values())
    if cond in ("all of them", "all of selection*"):
        return all(results.values()) if results else False
    if cond in ("1 of them", "any of them", "1 of selection*"):
        return any(results.values())
    if " or " in cond:
        return any(_eval_condition(p.strip(), results, sels) for p in cond.split(" or "))
    if " and " in cond:
        return all(_eval_condition(p.strip(), results, sels) for p in cond.split(" and "))
    return results.get(cond, False)


class SigmaSet:
    """A loaded set of Sigma rules that can be evaluated against events."""

    def __init__(self, rules: list[dict] | None = None) -> None:
        self.rules = [r for r in (rules or []) if isinstance(r, dict) and r.get("detection")]

    def add_yaml(self, text: str) -> int:
        new = load_rules(text)
        self.rules.extend(r for r in new if r.get("detection"))
        return len(new)

    def evaluate(self, event) -> list[dict]:
        """Return the metadata of every rule that matches *event*."""
        hits = []
        for r in self.rules:
            if match(r, event):
                hits.append({"title": r.get("title", "?"), "level": r.get("level", "medium"),
                             "id": r.get("id"), "tags": r.get("tags", [])})
        return hits


def self_test() -> tuple[bool, str]:
    """Verify selection/condition/modifier matching against synthetic events."""
    class _Ev:
        def __init__(self, module, message, **d):
            self.module, self.message, self.details = module, message, d
            self.severity = None

    rule = {
        "title": "Suspicious PowerShell EncodedCommand",
        "level": "high",
        "detection": {
            "selection": {"image|endswith": "powershell.exe",
                          "cmdline|contains": "-enc"},
            "filter": {"user": "SYSTEM"},
            "condition": "selection and not filter",
        },
    }
    hit = _Ev("PROC", "spawn", image=r"C:\Windows\System32\powershell.exe",
              cmdline="powershell -enc ZQBj", user="alice")
    miss_sys = _Ev("PROC", "spawn", image="powershell.exe", cmdline="-enc x", user="SYSTEM")
    miss_cmd = _Ev("PROC", "spawn", image="powershell.exe", cmdline="Get-Process", user="alice")

    or_rule = {"title": "lolbins", "detection": {
        "sel": {"image|endswith": ["mshta.exe", "regsvr32.exe"]}, "condition": "sel"}}
    ss = SigmaSet([rule, or_rule])
    h1 = ss.evaluate(hit)
    ok = (match(rule, hit) and not match(rule, miss_sys) and not match(rule, miss_cmd)
          and match(or_rule, _Ev("P", "x", image="a\\mshta.exe"))
          and len(h1) == 1 and h1[0]["level"] == "high")
    return ok, ("Sigma subset verified: selection + modifiers + 'and not filter' + list-OR"
                if ok else f"failed: hit={match(rule,hit)} sys={match(rule,miss_sys)} "
                           f"cmd={match(rule,miss_cmd)} evalhits={h1}")
