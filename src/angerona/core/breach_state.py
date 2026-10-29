"""First-party breach presentation contracts; display state grants no authority."""
from __future__ import annotations

from dataclasses import dataclass, replace
from collections import OrderedDict
import copy
import hashlib
import json
import math
import os
import queue
import re
import sys
import threading
import time

from angerona.core.eventbus import Event, Severity, is_remote_observe_only
from angerona.core.threat import event_disposition

_CASE = re.compile(r"[0-9a-f]{32}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ACTIONS = frozenset({"investigate", "trace", "isolate", "kill", "patch", "lift_lockdown", "review_resolved"})


@dataclass(frozen=True)
class BreachActionAvailability:
    action: str
    enabled: bool
    reason: str = ""
    confirmation_required: bool = True


@dataclass(frozen=True)
class BreachDisplaySnapshot:
    active: bool = False
    state: str = "monitoring"
    summary: str = ""
    case_id: str = ""
    containment_state: str = "not-requested"
    sequence: int = 0
    details: tuple[tuple[str, str], ...] = ()
    actions: tuple[BreachActionAvailability, ...] = ()


@dataclass(frozen=True)
class VerifiedBreachEvidence:
    """A bounded native observation, not a permission to mutate the host."""

    case_id: str
    event: Event
    authorized_actions: frozenset[str]


class _ReviewBudget:
    """Bound one receipt-review pass and immediately honor controller STOP."""

    def __init__(self, stop):
        self._stop = stop
        self._deadline = time.monotonic() + 3.0

    def is_set(self):
        return self._stop.is_set() or time.monotonic() >= self._deadline


def _bounded_tree(value, *, budget=65536) -> bool:
    pending = [(value, 0)]
    visited = 0
    while pending:
        item, depth = pending.pop()
        visited += 1
        if visited > 512 or depth > 8:
            return False
        if type(item) is str:
            budget -= len(item) * 4
        elif type(item) in (int, float):
            if type(item) is float and not math.isfinite(item):
                return False
            budget -= 32
        elif item is None or type(item) is bool:
            budget -= 8
        elif type(item) is dict:
            if len(item) > 64 or any(type(key) is not str for key in item):
                return False
            pending.extend((key, depth + 1) for key in item)
            pending.extend((part, depth + 1) for part in item.values())
        elif type(item) in (tuple, list):
            if len(item) > 128:
                return False
            pending.extend((part, depth + 1) for part in item)
        else:
            return False
        if budget < 0:
            return False
    return True


def _plain(value, limit=512) -> str:
    text = value if type(value) is str else ""
    text = " ".join(text.split())[:limit]
    return re.sub(r"(?i)(?:\bBearer\s+\S+|\b(?:password|secret|token|api[_-]?key)\s*[=:]\s*\S+)",
                  "[redacted]", text)


def verified_breach(event, bus, modules, *, now=None, require_fresh=True) -> VerifiedBreachEvidence | None:
    """Authenticate a live, explicitly actionable native detector observation.

    Severity alone, imported tool results and an unarmed bus never establish a
    breach. Explicit producer uncertainty remains uncertainty, including the
    SpywareGuard single-rule records that publish ``spyware_confirmed=False``.
    """
    from angerona.core.module_base import BaseModule
    from angerona.modules.adversary_combat import AdversaryCombat

    if type(event) is not Event or not isinstance(modules, dict):
        return None
    # Archived HMAC integrity does not prove a live producer identity. The
    # manager-issued mesh receipt also binds the current admitted generation.
    if not getattr(bus, "integrity_enabled", False) or not getattr(bus, "mesh_required", False):
        return None
    try:
        if not _bounded_tree(event.details):
            return None
        producer = modules.get(event.module)
        if (not isinstance(producer, BaseModule) or producer.name != event.module
                or not type(producer).__module__.startswith("angerona.modules.")
                or type(producer).__module__ == "angerona.modules.adversary_combat"):
            return None
        if bus.verify(event) is not True:
            return None
        if is_remote_observe_only(event) or event_disposition(event) != "active":
            return None
        if type(event.ts) not in (int, float) or not math.isfinite(event.ts):
            return None
        age = (time.time() if now is None else now) - event.ts
        if require_fresh and not -1 <= age <= 30:
            return None
        details = event.details
        # event_disposition retains legacy severity fallbacks for dashboards.
        # A breach latch requires the producer's explicit active evidence.
        if details.get("active_attack") is not True and details.get("active_exploitation") is not True:
            return None
        if any(details.get(key) is False for key in ("breach_confirmed", "malware_confirmed", "spyware_confirmed")):
            return None
        if details.get("observation_only") is True:
            return None
        actions = AdversaryCombat._response_actions(event)
        if not actions or event.severity < Severity.HIGH:
            return None
        exact_hash = details.get("observed_content_sha256")
        evidence = details.get("evidence")
        matched_hash = details.get("matched_sha256")
        if type(evidence) is dict and evidence.get("indicator_kind") == "sha256":
            matched_hash = evidence.get("indicator")
        hash_confirmed = bool(type(exact_hash) is str and _HASH.fullmatch(exact_hash)
                              and exact_hash == matched_hash)
        if event.severity < Severity.CRITICAL and not hash_confirmed:
            return None
        contract = details["response_contract"]
        kind = details.get("finding_code") or details.get("kind") or details.get("event_type")
        if type(kind) is not str or not 1 <= len(kind) <= 100:
            return None
        # The stable identity excludes timestamps/message text and still binds
        # a new process generation, file digest or peer to a new case.
        identity = {"producer": event.module, "kind": kind,
                    "targets": contract["targets"], "observed_sha256": exact_hash,
                    "matched_sha256": matched_hash, "path": details.get("path"),
                    "pid": details.get("pid"), "process_create_time": details.get("process_create_time")}
        raw = json.dumps(identity, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        case_id = hashlib.sha256(b"angerona-confirmed-breach-v1\0" + raw).hexdigest()[:32]
        return VerifiedBreachEvidence(case_id, copy.deepcopy(event), actions)
    except (ValueError, TypeError, AttributeError, RecursionError, OverflowError, RuntimeError):
        return None


def protect_authority() -> tuple[bool, str]:
    """Observe existing installed authority; this function never requests UAC."""
    if os.name != "nt":
        return False, "An accepted native host-lockdown adapter is unavailable on this platform."
    if not getattr(sys, "frozen", False):
        return False, "Source Observe mode cannot authorize host network or process mutation."
    try:
        from angerona.core.privilege import is_admin
        from angerona.core.windows_package_identity import verify_current_msix_authority
        if not is_admin() or not verify_current_msix_authority().trusted:
            return False, "Verified installed Protect and Administrator authority are required."
        return True, "Installed Protect and Administrator authority verified."
    except Exception:
        return False, "Installed response authority could not be verified."


class BreachStateController:
    """One bounded evidence worker; snapshots and action admission are memory-only."""

    def __init__(self, manager, *, start=True, clock=time.time):
        self.manager = manager
        self._clock = clock
        self._bus = getattr(manager, "bus", getattr(manager, "_bus", None))
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._events = queue.Queue(maxsize=64)
        self._requests = queue.Queue(maxsize=16)
        self._cases = OrderedDict()
        self._active_case = ""
        self._published_cases = ()
        self._sequence = 0
        self._snapshot = BreachDisplaySnapshot()
        self._pending = {}
        self._dropped = 0
        self._last_sync = 0.0
        self._thread = None
        if self._bus is not None:
            self._bus.subscribe(self._enqueue_event, delivery_budget_ms=5)
        if start:
            self._thread = threading.Thread(target=self._run, name="BreachEvidenceReview", daemon=True)
            self._thread.start()

    def _enqueue_event(self, event):
        details = event.details if type(event) is Event else None
        if (not self._stop.is_set() and type(event) is Event and event.severity >= Severity.HIGH
                and type(details) is dict and details.get("response_authorized") is True):
            try:
                self._events.put_nowait(event)
            except queue.Full:
                with self._lock:
                    self._dropped += 1  # Originals remain in the bus/recorder.

    def snapshot(self) -> BreachDisplaySnapshot:
        with self._lock:
            return self._snapshot

    def request_action(self, case_id, action) -> bool:
        if (type(case_id) is not str or not _CASE.fullmatch(case_id)
                or type(action) is not str or action not in _ACTIONS or self._stop.is_set()):
            return False
        with self._lock:
            if case_id != self._active_case or not any(row.action == action and row.enabled for row in self._snapshot.actions):
                return False
            reviewed_cases = self._published_cases
        try:
            self._requests.put_nowait((case_id, action, reviewed_cases))
            return True
        except queue.Full:
            return False

    def request_stop(self):
        self._stop.set()
        if self._bus is not None:
            self._bus.unsubscribe(self._enqueue_event)

    def close(self, timeout=2.0) -> bool:
        self.request_stop()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, min(float(timeout), 5.0)))
        return thread is None or not thread.is_alive()

    def _combat(self):
        from angerona.modules.adversary_combat import AdversaryCombat
        module = getattr(self.manager, "modules", {}).get("Adversary Combat")
        return module if isinstance(module, AdversaryCombat) else None

    def _publish(self, case):
        evidence = case["evidence"]
        case_id = evidence.case_id if evidence is not None else case["case_id"]
        if case_id != self._active_case:
            return
        allowed, reason = protect_authority()
        combat = self._combat()
        ready = bool(combat and combat.response_snapshot().get("ready") is True)
        fresh = evidence is not None and -1 <= self._clock() - evidence.event.ts <= 30
        authorized_actions = evidence.authorized_actions if evidence is not None else frozenset()
        actions = [BreachActionAvailability("investigate", True, confirmation_required=False),
                   BreachActionAvailability("trace", True, confirmation_required=False)]
        state = case["containment"]
        for action, contract in (("isolate", "isolate_host"), ("kill", "terminate_process")):
            enabled = allowed and ready and fresh and contract in authorized_actions and not case["resolved"]
            explanation = reason if not allowed else "A ready response worker and detector-authorized exact target are required."
            if action == "isolate" and state == "locked-down":
                enabled, explanation = False, "Verified lockdown is already active."
            actions.append(BreachActionAvailability(action, enabled, "" if enabled else explanation))
        actions.append(BreachActionAvailability("patch", False, "No reviewed patch operation is bound to this detector observation."))
        lift_ready = bool(combat and combat.status == "running" and combat._response_initialized and not combat.stopping)
        can_lift = allowed and lift_ready and case.get("receipt_available", state == "locked-down") and state in {"locked-down", "unknown"}
        actions.append(BreachActionAvailability("lift_lockdown", can_lift,
            "" if can_lift else (reason if not allowed else "No verified applied managed lockdown is available to lift.")))
        unresolved_lockdown = state in {"requested", "locked-down", "unknown"}
        actions.append(BreachActionAvailability("review_resolved", not unresolved_lockdown and not case["resolved"],
            "Complete, lift or verify the existing lockdown before resolving this review." if unresolved_lockdown else ""))
        event = evidence.event if evidence is not None else None
        details = (("Native producer", event.module if event else case.get("producer", "Verified action journal")),
                   ("Observed", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(event.ts if event else case.get("observed_at", 0)))),
                   ("Evidence digest", (event.hmac_sig or event.mesh_sig) if event else case.get("receipt_digest", "")), ("Containment", state),
                   ("Review", case.get("message", "")), ("Requested scope", "All external traffic: Ethernet, Wi-Fi and other interfaces; IPv4/IPv6, inbound/outbound, all protocols and ports."),
                   ("Authority", reason), ("Coverage", "Lockdown requires effective local-policy and native-rule verification. Packet drops and administrator/kernel tampering are not independently attested."))
        if event is not None:
            native_details = event.details
            targets = native_details["response_contract"]["targets"]
            details += (("Authorized native actions", ", ".join(sorted(authorized_actions))),)
            if type(targets.get("pid")) is int:
                details += (("Observed PID / birth", f"{targets['pid']} / {targets.get('process_create_time')!s}"),)
            if type(targets.get("path")) is str:
                details += (("File target (bounded display)", _plain(targets["path"])),)
            if type(targets.get("remote_ips")) is list:
                details += (("Native peer IP targets", _plain(", ".join(str(value) for value in targets["remote_ips"]))),)
            if type(native_details.get("observed_content_sha256")) is str:
                details += (("Observed content SHA-256", _plain(native_details["observed_content_sha256"], 64)),)
        reviewed_cases = tuple(key for key, row in self._cases.items() if not row["resolved"])
        if len(reviewed_cases) > 1:
            # The global Lift applies to every case included in this review.
            # Publishing the exact bounded set also prevents a later-arriving
            # case from borrowing an earlier operator override.
            for offset in range(0, len(reviewed_cases), 8):
                details += ((f"Verified cases in this review {offset // 8 + 1}", ", ".join(reviewed_cases[offset:offset + 8])),)
        if self._dropped:
            details += (("Review queue coverage", f"{self._dropped} notices were not admitted; authenticated originals remain in the event bus/recorder."),)
        with self._lock:
            self._sequence += 1
            self._published_cases = reviewed_cases
            self._snapshot = BreachDisplaySnapshot(not case["resolved"], "resolved" if case["resolved"] else "breached",
                _plain(event.message if event else "A previously verified breach lockdown receipt requires review."), case_id, state, self._sequence, details, tuple(actions))

    def _accept_event(self, event):
        if self._stop.is_set():
            return
        evidence = verified_breach(event, self._bus, getattr(self.manager, "modules", {}), now=self._clock())
        if evidence is None:
            return
        case = self._cases.get(evidence.case_id)
        if case is None:
            if len(self._cases) >= 32:
                pending_cases = {key for key, _action in self._pending.values()}
                evict = next((key for key, row in self._cases.items()
                              if (key != self._active_case or row["resolved"]) and key not in pending_cases
                              and row["containment"] not in {"requested", "locked-down", "unknown"}), None)
                if evict is None:
                    self._dropped += 1
                    return
                self._cases.pop(evict)
            case = {"evidence": evidence, "containment": "not-requested", "resolved": False, "message": "Authenticated native active evidence; review exact source coverage.", "auto_requested": False}
            self._cases[evidence.case_id] = case
        else:
            case["evidence"] = evidence
        current = self._cases.get(self._active_case)
        with self._lock:
            if current is None or current["resolved"] or current["containment"] not in {"requested", "locked-down", "unknown"}:
                self._active_case = evidence.case_id
        self._publish(case)
        cfg = getattr(self.manager, "config", None)
        lifted = getattr(cfg, "breach_lifted_cases", ())
        if (getattr(cfg, "breach_auto_isolate_enabled", True) is True
                and evidence.case_id not in lifted and not case["auto_requested"] and not case["resolved"]):
            case["auto_requested"] = self._submit(case, "isolate", automatic=True)
        if self._active_case != evidence.case_id:
            self._publish(self._cases[self._active_case])

    def _submit(self, case, action, *, automatic=False, reviewed_cases=()):
        if self._stop.is_set():
            return False
        admitted = False
        combat = self._combat()
        if combat is None:
            if case["containment"] not in {"locked-down", "unknown"}:
                case["containment"] = "held"
            case["message"] = "The response worker is unavailable; no new network restriction is verified."
        else:
            request_id = __import__("secrets").token_hex(16)
            evidence = case["evidence"]
            case_id = evidence.case_id if evidence is not None else case["case_id"]
            if combat.request_breach_action(evidence.event if evidence else None, case_id, action, request_id,
                                            automatic=automatic, reviewed_cases=reviewed_cases):
                admitted = True
                self._pending[request_id] = (case_id, action)
                case.update(containment="requested" if action == "isolate" else case["containment"], message="Response queued; completion and native scope remain unverified.")
            else:
                if case["containment"] not in {"locked-down", "unknown"}:
                    case["containment"] = "held"
                case["message"] = "Response admission is held; no new network restriction is verified."
        self._publish(case)
        return admitted

    def _process_request(self, case_id, action, reviewed_cases=()):
        with self._lock:
            case = self._cases.get(case_id)
        if case is None:
            return
        if action == "review_resolved":
            if case["containment"] not in {"requested", "locked-down", "unknown"}:
                case.update(resolved=True, message="Operator marked this case reviewed; this does not attest eradication or change a security baseline.")
        elif action in {"isolate", "kill", "lift_lockdown"}:
            if not case["resolved"] or action == "lift_lockdown":
                self._submit(case, action, reviewed_cases=reviewed_cases if action == "lift_lockdown" else ())
        self._publish(case)

    def _sync_results(self):
        combat = self._combat()
        if combat is None:
            return
        for request_id, (case_id, action) in tuple(self._pending.items()):
            result = combat.breach_action_result(request_id)
            if not result or result.get("state") == "queued":
                continue
            self._pending.pop(request_id, None)
            case = self._cases.get(case_id)
            if case is None:
                continue
            state = result.get("state")
            if action == "isolate":
                case["containment"] = ("locked-down" if state == "applied" and result.get("scope_verified") is True
                                       else "unknown" if state == "unknown" else "held")
                case["receipt_available"] = case["containment"] == "locked-down"
            elif action == "lift_lockdown":
                if state == "lifted":
                    case["containment"] = "lifted"
                    case["receipt_available"] = False
                elif state == "unknown":
                    case["containment"] = "unknown"
            case["message"] = _plain(result.get("message"))
            self._publish(case)

    def _sync_receipts(self):
        """Recover only authenticated managed receipts, outside the UI thread.

        An old receipt is not a substitute native target or fresh mutation
        authority. It can latch a review and expose exact receipt-bound Undo.
        No raw detector/report text is deserialized into an actionable event.
        """
        if self._clock() - self._last_sync < 2:
            return
        self._last_sync = self._clock()
        combat = self._combat()
        if combat is None or not combat._response_initialized or self._stop.is_set():
            return
        records = combat.list_actions(limit=512)
        budget = _ReviewBudget(self._stop)
        grouped = OrderedDict()
        for record in records:
            details = record.get("details")
            if (record.get("integrity_status") != "verified" or record.get("action") != "isolate_host"
                    or type(details) is not dict or details.get("lockdown_scope_version") != 1
                    or type(details.get("breach_case_id")) is not str or not _CASE.fullmatch(details["breach_case_id"])):
                continue
            case_id = details["breach_case_id"]
            if case_id not in grouped and len(grouped) >= 32:
                continue
            grouped.setdefault(case_id, []).append(record)
        allowed = protect_authority()[0]
        active_receipts = []
        for case_id, receipts in grouped.items():
            if self._stop.is_set():
                return
            active = [row for row in receipts if not row.get("undone") and row.get("status") in {"applied", "recovery_required"}]
            # A committed Undo is the durable counterpart of the operator
            # preference. Restoring the suppression never grants authority.
            if not active and any(row.get("undone") for row in receipts) and not combat._breach_is_lifted(case_id):
                try:
                    combat._record_breach_lift([case_id])
                except Exception:
                    pass  # The signed Undo still establishes the lifted state.
            case = self._cases.get(case_id)
            if case is None:
                if len(self._cases) >= 32:
                    continue  # Do not evict an active response awaiting review.
                latest = receipts[0]
                case = {"case_id": case_id, "evidence": None, "resolved": False,
                        "producer": _plain(latest.get("trigger_module"), 100),
                        "observed_at": latest.get("trigger_ts", 0),
                        "receipt_digest": _plain(latest.get("record_hmac"), 128),
                        "containment": "unknown" if active else "lifted", "auto_requested": True,
                        "message": "A verified native response receipt was recovered; no fresh process target is inferred."}
                self._cases[case_id] = case
                with self._lock:
                    if not self._active_case:
                        self._active_case = case_id
            if not active:
                case["receipt_available"] = False
                if case["containment"] in {"locked-down", "unknown"}:
                    case["containment"] = "lifted"
            else:
                active_receipts.append(case_id)
                case["receipt_available"] = True
                verified_scope = allowed and all(
                    row.get("status") == "applied" and row["details"].get("lockdown_scope_verified") is True
                    and row["details"].get("lockdown_policy_verified") is True
                    and type(row["details"].get("rules")) is list
                    and combat._valid_rule_set("isolate_host", row["details"]["rules"])
                    for row in active)
                if verified_scope and not self._stop.is_set():
                    verified_scope = (combat._lockdown_profiles_enabled(cancel=budget)
                                      and combat._lockdown_effective_policy(cancel=budget)) and all(
                        combat._lockdown_rule_scope(rule, rule.rsplit("-", 1)[-1], cancel=budget)
                        for row in active for rule in row["details"]["rules"])
                case["containment"] = "locked-down" if verified_scope else "unknown"
                if not verified_scope:
                    case["message"] = (combat._lockdown_policy_reason
                        or "The recovered receipt lacks current effective-policy or native-scope proof; restrictions require review.")
            self._publish(case)
        current = self._cases.get(self._active_case)
        if active_receipts and (current is None or current["containment"] in {"lifted", "held", "not-requested"}):
            # A partial global Lift may have removed the displayed receipt
            # while another owned case remains restricted. Keep its exact Undo
            # reachable rather than stranding the dashboard on the lifted one.
            with self._lock:
                self._active_case = active_receipts[0]
            self._publish(self._cases[self._active_case])

    def process_once(self):
        if self._stop.is_set():
            return
        try:
            request = self._requests.get_nowait()
        except queue.Empty:
            pass
        else:
            self._process_request(*request)
        for _ in range(8):
            try:
                event = self._events.get_nowait()
            except queue.Empty:
                break
            else:
                self._accept_event(event)
        self._sync_results()
        self._sync_receipts()
        cfg = getattr(self.manager, "config", None)
        if getattr(cfg, "breach_auto_isolate_enabled", True) is True:
            lifted = getattr(cfg, "breach_lifted_cases", ())
            for case in tuple(self._cases.values()):
                evidence = case["evidence"]
                if (evidence is not None and not case["auto_requested"] and not case["resolved"] and evidence.case_id not in lifted
                        and -1 <= self._clock() - evidence.event.ts <= 30):
                    case["auto_requested"] = self._submit(case, "isolate", automatic=True)

    def _run(self):
        while not self._stop.is_set():
            try:
                self.process_once()
            except Exception as error:
                # Retain the latch and surface a bounded coverage gap without
                # asking the UI to do provider IO or exposing exception text.
                notice = ("Review worker coverage", f"Review held after {type(error).__name__}; authenticated originals and prior containment state are preserved.")
                with self._lock:
                    if notice not in self._snapshot.details:
                        self._sequence += 1
                        details = tuple(row for row in self._snapshot.details if row[0] != notice[0])
                        self._snapshot = replace(self._snapshot, sequence=self._sequence, details=(*details, notice))
            self._stop.wait(.25)


_FACTORY_LOCK = threading.Lock()


def ensure_breach_controller(manager) -> BreachStateController:
    with _FACTORY_LOCK:
        current = getattr(manager, "_breach_state_controller", None)
        if type(current) is BreachStateController:
            return current
        controller = BreachStateController(manager)
        manager._breach_state_controller = controller
        return controller
