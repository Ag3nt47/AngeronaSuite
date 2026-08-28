"""core/sigma_engine.py — a constrained Sigma detection-rule engine.

Sigma is the community standard for portable detection rules. Angerona does not
claim full Sigma compatibility: each imported document must pass an explicit
admission check for the locally implemented subset, and every result carries a
bounded receipt explaining acceptance or refusal.

This is an MVP matcher (not the full spec): it supports a `detection:` block of
named selection maps with field modifiers `contains`/`startswith`/`endswith`/`re`,
list values (OR), and a `condition` of the form `sel`, `sel1 and sel2`,
`sel1 or sel2`, `all of them`, `1 of them` (optionally with `and not filter`).
Events are matched against a flattened field dict (module, message, + details).

Logsource taxonomies, correlations, chained modifiers, wildcards, aggregation,
parentheses, and arbitrary boolean expressions are refused rather than silently
mis-evaluated. Pure/local. YAML loading uses PyYAML if present.
"""
from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass

MAX_RULE_TEXT_BYTES = 4 * 1024 * 1024
MAX_RULE_DOCUMENTS = 2000
MAX_RULE_NODES = 100_000
MAX_RULE_DEPTH = 16
MAX_RULE_STRING = 4096
SUPPORTED_SIGMA_SUBSET = (
    "Angerona constrained Sigma rule subset: named map selections; exact, "
    "contains, startswith, endswith, or re values; list-value OR; simple "
    "selector AND/OR; 1/all of them or prefix*; optional trailing AND NOT."
)


@dataclass(frozen=True)
class SigmaAdmissionReceipt:
    """Bounded, machine-readable truth about a Sigma import attempt."""

    accepted: bool
    code: str
    reason: str
    admitted_count: int = 0
    rejected_count: int = 0
    subset: str = SUPPORTED_SIGMA_SUBSET

    def as_dict(self) -> dict:
        return asdict(self)


class SigmaRuleList(list[dict]):
    """List-compatible import result carrying its admission receipt."""

    def __init__(self, rules=(), *, receipt: SigmaAdmissionReceipt) -> None:
        super().__init__(rules)
        self.receipt = receipt


def _receipt(
    accepted: bool,
    code: str,
    reason: str,
    *,
    admitted: int = 0,
    rejected: int = 0,
) -> SigmaAdmissionReceipt:
    safe_code = re.sub(r"[^A-Z0-9_]", "_", str(code).upper())[:64] or "UNKNOWN"
    return SigmaAdmissionReceipt(
        accepted=accepted,
        code=safe_code,
        reason=str(reason)[:256],
        admitted_count=max(0, int(admitted)),
        rejected_count=max(0, int(rejected)),
    )


def _bounded_yaml_value(value, budget: list[int], depth: int = 0) -> bool:
    if depth > MAX_RULE_DEPTH:
        return False
    budget[0] -= 1
    if budget[0] < 0:
        return False
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, int):
        return -(2**63) <= value <= 2**63 - 1
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, str):
        return len(value) <= MAX_RULE_STRING
    if isinstance(value, list):
        return len(value) <= 4096 and all(
            _bounded_yaml_value(item, budget, depth + 1) for item in value
        )
    if isinstance(value, dict):
        return len(value) <= 1024 and all(
            isinstance(key, str)
            and 0 < len(key) <= 256
            and _bounded_yaml_value(item, budget, depth + 1)
            for key, item in value.items()
        )
    return False


_SELECTOR = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,127}$")
_SUPPORTED_MODIFIERS = frozenset({"contains", "startswith", "endswith", "re"})


def _selection_supported(selection: object) -> tuple[bool, str]:
    maps = selection if isinstance(selection, list) else [selection]
    if not maps or len(maps) > 256:
        return False, "selection list must contain 1 to 256 maps"
    if not all(isinstance(item, dict) and item for item in maps):
        return False, "keyword and non-map selections are unsupported"
    for item in maps:
        if len(item) > 256:
            return False, "selection map exceeds 256 fields"
        for raw_key, raw_expected in item.items():
            if not isinstance(raw_key, str):
                return False, "selection field names must be strings"
            parts = raw_key.split("|")
            field = parts[0]
            if not field or len(field) > 256:
                return False, "selection field name is empty or too long"
            if len(parts) > 2:
                return False, "chained Sigma modifiers are unsupported"
            modifier = parts[1].lower() if len(parts) == 2 else ""
            if modifier and modifier not in _SUPPORTED_MODIFIERS:
                return False, f"unsupported Sigma modifier: {modifier[:64]}"
            values = raw_expected if isinstance(raw_expected, list) else [raw_expected]
            if not values or len(values) > 256:
                return False, "selection values must contain 1 to 256 scalars"
            for value in values:
                if value is None or not isinstance(value, (str, int, bool)):
                    return False, "selection values must be strings, integers, or booleans"
                if isinstance(value, str):
                    if len(value) > MAX_RULE_STRING:
                        return False, "selection string exceeds the bounded maximum"
                    if value == "":
                        return False, "empty Sigma string values are unsupported"
                    if not modifier and ("*" in value or "?" in value):
                        return False, "Sigma wildcard values are unsupported"
                    if modifier == "re":
                        if len(value) > 512:
                            return False, "regular expression exceeds 512 characters"
                        if "(?" in value or re.search(r"\\[1-9]", value):
                            return False, "regex extensions and backreferences are unsupported"
                        if re.search(r"\([^)]*[+*{][^)]*\)\s*[+*{]", value):
                            return False, "nested quantified regular expressions are unsafe"
                        try:
                            re.compile(value)
                        except re.error:
                            return False, "regular expression is invalid"
                elif modifier == "re":
                    return False, "regular expression values must be strings"
    return True, ""


def _condition_supported(condition: object, names: set[str]) -> tuple[bool, str]:
    if not isinstance(condition, str) or not condition.strip():
        return False, "detection.condition is required"
    cond = " ".join(condition.strip().lower().split())
    if len(cond) > 1024 or any(token in cond for token in ("(", ")", "|")):
        return False, "condition uses unsupported grouping or syntax"
    if cond.count(" and not ") > 1:
        return False, "condition supports at most one trailing AND NOT selector"
    if " and not " in cond:
        cond, negated = cond.rsplit(" and not ", 1)
        if negated not in names:
            return False, "condition references an unknown negated selector"
    if cond in {"all of them", "1 of them", "any of them"}:
        return True, ""
    pattern = re.fullmatch(r"(all|1) of ([a-z_][a-z0-9_-]*)\*", cond)
    if pattern:
        if any(name.startswith(pattern.group(2)) for name in names):
            return True, ""
        return False, "condition prefix does not match a selector"
    has_and = " and " in cond
    has_or = " or " in cond
    if has_and and has_or:
        return False, "mixed AND/OR precedence is unsupported"
    parts = cond.split(" and " if has_and else " or " if has_or else "\0")
    if not parts or any(part not in names for part in parts):
        return False, "condition references an unknown or unsupported selector"
    return True, ""


def _rule_supported(
    rule: object, *, require_rule_envelope: bool = True
) -> tuple[bool, str, str]:
    if not isinstance(rule, dict):
        return False, "DOCUMENT_NOT_OBJECT", "Sigma document must be a map"
    if "correlation" in rule:
        return False, "UNSUPPORTED_CORRELATION", "Sigma correlation rules are unsupported"
    if require_rule_envelope:
        title = rule.get("title")
        if not isinstance(title, str) or not title.strip() or len(title) > 512:
            return False, "INVALID_RULE", "Sigma title is required and must be bounded"
    if rule.get("logsource") not in (None, {}):
        return (
            False,
            "UNSUPPORTED_LOGSOURCE",
            "logsource taxonomy matching is not implemented; rule refused",
        )
    detection = rule.get("detection")
    if not isinstance(detection, dict):
        return False, "INVALID_DETECTION", "detection must be a map"
    selections = {key: value for key, value in detection.items() if key != "condition"}
    if not selections:
        return False, "INVALID_DETECTION", "detection requires at least one selection"
    names: set[str] = set()
    for raw_name, selection in selections.items():
        if not isinstance(raw_name, str) or _SELECTOR.fullmatch(raw_name) is None:
            return False, "UNSUPPORTED_SELECTOR", "selection identifier is unsupported"
        name = raw_name.lower()
        if name in names:
            return False, "AMBIGUOUS_SELECTOR", "selection identifiers collide by case"
        names.add(name)
        ok, reason = _selection_supported(selection)
        if not ok:
            return False, "UNSUPPORTED_SELECTION", reason
    ok, reason = _condition_supported(detection.get("condition"), names)
    if not ok:
        return False, "UNSUPPORTED_CONDITION", reason
    return True, "ADMITTED", "rule is supported by the constrained subset"


def load_rules(text: str) -> SigmaRuleList:
    """Parse and explicitly admit a bounded batch of Sigma YAML documents.

    The return value remains list-compatible, but callers can and should inspect
    ``result.receipt``. A single unsupported document refuses the whole batch so
    partial imports cannot look like complete success.
    """
    try:
        import yaml  # type: ignore
    except Exception:
        return SigmaRuleList(receipt=_receipt(
            False, "DEPENDENCY_UNAVAILABLE", "PyYAML is unavailable", rejected=1
        ))
    if not isinstance(text, str):
        return SigmaRuleList(receipt=_receipt(
            False, "INVALID_INPUT", "Sigma input must be text", rejected=1
        ))
    try:
        if len(text.encode("utf-8")) > MAX_RULE_TEXT_BYTES:
            return SigmaRuleList(receipt=_receipt(
                False, "LIMIT_EXCEEDED", "Sigma input exceeds 4 MiB", rejected=1
            ))

        class NoAliasSafeLoader(yaml.SafeLoader):
            def compose_node(self, parent, index):
                if self.check_event(yaml.AliasEvent):
                    raise yaml.YAMLError("YAML aliases are unsupported")
                return super().compose_node(parent, index)

        rules: list[dict] = []
        budget = [MAX_RULE_NODES]
        for document in yaml.load_all(text, Loader=NoAliasSafeLoader):
            if len(rules) >= MAX_RULE_DOCUMENTS:
                return SigmaRuleList(receipt=_receipt(
                    False, "LIMIT_EXCEEDED", "Sigma batch exceeds 2000 documents",
                    rejected=len(rules) + 1,
                ))
            if not _bounded_yaml_value(document, budget):
                return SigmaRuleList(receipt=_receipt(
                    False, "UNSAFE_OR_UNBOUNDED_YAML",
                    "Sigma document contains an unsupported or unbounded YAML value",
                    rejected=len(rules) + 1,
                ))
            supported, code, reason = _rule_supported(document)
            if not supported:
                return SigmaRuleList(receipt=_receipt(
                    False, code, reason, rejected=len(rules) + 1
                ))
            rules.append(document)
        if not rules:
            return SigmaRuleList(receipt=_receipt(
                False, "EMPTY_INPUT", "Sigma input contains no rule documents"
            ))
        return SigmaRuleList(rules, receipt=_receipt(
            True, "ADMITTED", "all rules admitted by the constrained subset",
            admitted=len(rules),
        ))
    except Exception:
        return SigmaRuleList(receipt=_receipt(
            False, "YAML_PARSE_ERROR", "Sigma YAML could not be parsed", rejected=1
        ))


def event_fields(event) -> dict:
    """Flatten an Angerona event into a Sigma-matchable field dict."""
    det = getattr(event, "details", None)
    fields = {"module": getattr(event, "module", ""),
              "message": getattr(event, "message", ""),
              "severity": getattr(getattr(event, "severity", None), "name", "")}
    if isinstance(det, dict):
        for k, v in det.items():
            key = str(k)
            if key not in fields:
                fields[key] = v
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
            # Sigma regular expressions are case-sensitive unless a supported
            # case transformation is explicitly requested. This subset refuses
            # chained transformations, so plain ``re`` stays case-sensitive.
            return re.search(ev, fv) is not None
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
        parts = key.split("|")
        if len(parts) > 2:
            return False
        field = parts[0]
        modifier = parts[1] if len(parts) == 2 else ""
        fv = fields.get(field)
        vals = expected if isinstance(expected, list) else [expected]
        if not any(_match_value(fv, v, modifier or None) for v in vals):
            return False
    return True


def match(rule: dict, event) -> bool:
    """True only when a supported subset rule matches *event*; never raises."""
    try:
        supported, _code, _reason = _rule_supported(
            rule, require_rule_envelope=False
        )
        if not supported:
            return False
        det = rule.get("detection") or {}
        if not isinstance(det, dict):
            return False
        condition = str(det.get("condition", "")).strip().lower()
        sels = {k: v for k, v in det.items() if k != "condition"}
        fields = event_fields(event)
        results = {
            str(name).lower(): _match_selection(sel, fields)
            for name, sel in sels.items()
        }

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
    if cond == "all of them":
        eligible = [value for name, value in results.items() if not name.startswith("_")]
        return all(eligible) if eligible else False
    if cond in ("1 of them", "any of them"):
        return any(value for name, value in results.items() if not name.startswith("_"))
    pattern = re.fullmatch(r"(all|1) of ([a-z_][a-z0-9_-]*)\*", cond)
    if pattern:
        selected = [
            value for name, value in results.items()
            if name.startswith(pattern.group(2))
        ]
        if not selected:
            return False
        return all(selected) if pattern.group(1) == "all" else any(selected)
    if " or " in cond:
        return any(_eval_condition(p.strip(), results, sels) for p in cond.split(" or "))
    if " and " in cond:
        return all(_eval_condition(p.strip(), results, sels) for p in cond.split(" and "))
    return results.get(cond, False)


class SigmaSet:
    """A loaded set of admitted subset rules that can be evaluated locally."""

    def __init__(self, rules: list[dict] | None = None) -> None:
        accepted: list[dict] = []
        rejected = 0
        for rule in rules or []:
            supported, _code, _reason = _rule_supported(rule)
            if supported:
                accepted.append(rule)
            else:
                rejected += 1
        self.rules = accepted
        self.last_admission = _receipt(
            rejected == 0,
            "ADMITTED" if rejected == 0 else "UNSUPPORTED_RULE",
            "direct rules admitted" if rejected == 0 else "one or more direct rules were refused",
            admitted=len(accepted),
            rejected=rejected,
        )

    def add_yaml(self, text: str) -> int:
        new = load_rules(text)
        self.last_admission = new.receipt
        if not new.receipt.accepted:
            return 0
        self.rules.extend(new)
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
    return ok, ("Constrained Sigma subset verified: selection + modifiers + "
                "'and not filter' + list-OR + explicit admission receipts"
                if ok else f"failed: hit={match(rule,hit)} sys={match(rule,miss_sys)} "
                           f"cmd={match(rule,miss_cmd)} evalhits={h1}")
