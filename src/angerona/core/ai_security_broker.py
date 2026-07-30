"""Local-first policy boundary for untrusted AI security output.

No model or network client exists here. Callers supply model output as data,
which is validated before it can become a recommendation, plan, or typed tool
invocation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
import threading
import time
from dataclasses import asdict, dataclass, replace
from enum import Enum
from typing import Any, Callable, Mapping

MAX_INPUT_CHARS = 32_000
MAX_OUTPUT_CHARS = 64_000
MAX_TOOL_RESULT_CHARS = 64_000
MAX_EVIDENCE_IDS = 128
MAX_TOOL_ARGUMENTS = 32
MAX_PENDING_EXECUTIONS = 4096
DEFAULT_EXECUTION_TTL_SECONDS = 30
_TOOL_NAME = re.compile(r"^[a-z][a-z0-9_.-]{1,127}$")
_ARGUMENT_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_MODEL_BASE_FIELDS = frozenset({"confidence", "abstained", "abstention_reason", "conclusions"})
_MODEL_TOOL_FIELDS = frozenset({"tool_name", "tool_arguments"})


class AIMode(str, Enum):
    EXPLAIN = "explain"
    RECOMMEND = "recommend"
    PLAN = "plan"
    EXECUTE = "execute"


@dataclass(frozen=True)
class ModelProvenance:
    provider: str
    model: str
    version: str
    local: bool = True

    def __post_init__(self) -> None:
        if (
            not all(
                isinstance(value, str) and value and len(value) <= 256
                for value in (self.provider, self.model, self.version)
            )
            or type(self.local) is not bool
        ):
            raise ValueError("complete model provenance is required")


@dataclass(frozen=True)
class EgressDecision:
    cloud_allowed: bool = False
    operator_approved: bool = False
    reason: str = "local-only default"

    def __post_init__(self) -> None:
        if (
            type(self.cloud_allowed) is not bool
            or type(self.operator_approved) is not bool
            or not isinstance(self.reason, str)
            or len(self.reason) > 1000
        ):
            raise ValueError("invalid egress decision")

    def permits(self, provenance: ModelProvenance) -> bool:
        return provenance.local or (
            self.cloud_allowed and self.operator_approved and bool(self.reason)
        )


@dataclass(frozen=True)
class AIRequest:
    request_id: str
    mode: AIMode
    prompt: str
    evidence_ids: tuple[str, ...]
    provenance: ModelProvenance
    egress: EgressDecision = EgressDecision()

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_ids, (tuple, list)):
            raise ValueError("evidence IDs must be a bounded sequence")
        object.__setattr__(self, "evidence_ids", tuple(self.evidence_ids))
        if (
            not isinstance(self.request_id, str)
            or not self.request_id
            or len(self.request_id) > 128
        ):
            raise ValueError("invalid request ID")
        if (
            not isinstance(self.mode, AIMode)
            or not isinstance(self.provenance, ModelProvenance)
            or not isinstance(self.egress, EgressDecision)
        ):
            raise ValueError("request requires typed mode, provenance, and egress")
        if (
            not isinstance(self.prompt, str)
            or not self.prompt
            or len(self.prompt) > MAX_INPUT_CHARS
        ):
            raise ValueError("input is empty or exceeds the bound")
        if len(self.evidence_ids) > MAX_EVIDENCE_IDS:
            raise ValueError("too many evidence IDs")
        if any(
            not isinstance(value, str) or not value or len(value) > 256
            for value in self.evidence_ids
        ):
            raise ValueError("evidence IDs must be non-empty bounded strings")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("duplicate evidence ID")
        if not self.egress.permits(self.provenance):
            raise ValueError("model provenance is not permitted by egress decision")

    def canonical(self) -> bytes:
        value = asdict(self)
        value["mode"] = self.mode.value
        return _canonical_json(value)


@dataclass(frozen=True)
class SecurityConclusion:
    text: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True)
class BrokerResponse:
    request_id: str
    mode: AIMode
    conclusions: tuple[SecurityConclusion, ...]
    confidence: int
    abstained: bool
    abstention_reason: str
    tool_name: str = ""
    tool_arguments: tuple[tuple[str, Any], ...] = ()
    authorized_at: float = 0
    expires_at: float = 0
    authorization_tag: str = ""
    tool_executed: bool = False
    tool_result: Any = None


@dataclass(frozen=True)
class AuditReceipt:
    request_id: str
    request_hash: str
    response_hash: str
    mode: str
    provider: str
    model: str
    version: str
    local: bool
    accepted: bool
    tool_name: str
    tool_executed: bool
    created_at: float
    receipt_hash: str


@dataclass(frozen=True)
class _Tool:
    validators: Mapping[str, Callable[[Any], Any]]
    handler: Callable[..., Any]


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("value must use finite JSON-safe types") from exc


def _response_authorization_body(response: BrokerResponse) -> bytes:
    return _canonical_json(
        {
            "request_id": response.request_id,
            "mode": response.mode.value,
            "conclusions": [asdict(item) for item in response.conclusions],
            "confidence": response.confidence,
            "abstained": response.abstained,
            "abstention_reason": response.abstention_reason,
            "tool_name": response.tool_name,
            "tool_arguments": list(response.tool_arguments),
            "authorized_at": response.authorized_at,
            "expires_at": response.expires_at,
            "tool_executed": response.tool_executed,
            "tool_result": response.tool_result,
        }
    )


class AISecurityBroker:
    def __init__(
        self,
        *,
        execution_enabled: bool = False,
        execution_ttl_seconds: int = DEFAULT_EXECUTION_TTL_SECONDS,
        clock: Callable[[], float] = time.time,
        audit_key: bytes | None = None,
    ) -> None:
        if type(execution_enabled) is not bool:
            raise ValueError("AI execution setting must be a boolean")
        if type(execution_ttl_seconds) is not int:
            raise ValueError("AI execution authorization TTL must be an integer")
        if not callable(clock):
            raise ValueError("AI broker clock must be callable")
        if audit_key is not None and not isinstance(audit_key, bytes):
            raise ValueError("AI broker audit key must be bytes")
        self.execution_enabled = execution_enabled
        ttl = int(execution_ttl_seconds)
        if not 1 <= ttl <= 300:
            raise ValueError("AI execution authorization TTL must be 1-300 seconds")
        if audit_key is not None and len(audit_key) < 32:
            raise ValueError("AI broker audit key must contain at least 32 bytes")
        self._execution_ttl = ttl
        self._clock = clock
        self._authorization_key = secrets.token_bytes(32)
        self._audit_key = secrets.token_bytes(32) if audit_key is None else bytes(audit_key)
        self._consumed: dict[str, float] = {}
        self._execution_lock = threading.Lock()
        self._tools: dict[str, _Tool] = {}

    def register_tool(
        self,
        name: str,
        *,
        validators: Mapping[str, Callable[[Any], Any]],
        handler: Callable[..., Any],
    ) -> None:
        if not isinstance(name, str) or not _TOOL_NAME.fullmatch(name):
            raise ValueError("tool name must use a bounded canonical identifier")
        if name in self._tools:
            raise ValueError("tool name must be non-empty and unique")
        if any(
            token in name.casefold()
            for token in ("shell", "powershell", "cmd", "code", "subprocess")
        ):
            raise ValueError("raw shell/code tools are forbidden")
        if (
            not isinstance(validators, Mapping)
            or not validators
            or len(validators) > MAX_TOOL_ARGUMENTS
            or any(
                not isinstance(key, str)
                or not _ARGUMENT_NAME.fullmatch(key)
                or not callable(validator)
                for key, validator in validators.items()
            )
            or not callable(handler)
        ):
            raise ValueError("typed tool validators are required")
        self._tools[name] = _Tool(dict(validators), handler)

    @staticmethod
    def _canonical_hash(value: Any) -> str:
        return hashlib.sha256(_canonical_json(value)).hexdigest()

    def _authorization_tag(self, response: BrokerResponse) -> str:
        return hmac.new(
            self._authorization_key,
            _response_authorization_body(response),
            hashlib.sha256,
        ).hexdigest()

    def validate(self, request: AIRequest, model_output: Mapping[str, Any]) -> BrokerResponse:
        if not isinstance(request, AIRequest):
            raise ValueError("request must use the typed AI request schema")
        if type(model_output) is not dict:
            raise ValueError("model output must be a plain JSON object")
        encoded = _canonical_json(model_output)
        if len(encoded) > MAX_OUTPUT_CHARS:
            raise ValueError("model output exceeds the bound")
        if request.mode is not AIMode.EXECUTE and set(model_output) & _MODEL_TOOL_FIELDS:
            raise ValueError("tools are allowed only in execute mode")
        expected_fields = _MODEL_BASE_FIELDS
        if request.mode is AIMode.EXECUTE:
            expected_fields |= _MODEL_TOOL_FIELDS
        missing = expected_fields - set(model_output)
        unknown = set(model_output) - expected_fields
        if missing or unknown:
            raise ValueError(
                f"model output schema mismatch (missing={len(missing)}, unknown={len(unknown)})"
            )
        confidence = model_output.get("confidence")
        if type(confidence) is not int or not 0 <= confidence <= 100:
            raise ValueError("confidence must be an integer from 0 to 100")
        abstained = model_output.get("abstained")
        if type(abstained) is not bool:
            raise ValueError("explicit abstention state is required")
        reason = model_output["abstention_reason"]
        if not isinstance(reason, str) or len(reason) > 4000:
            raise ValueError("abstention reason must be a bounded string")
        if abstained and not reason:
            raise ValueError("abstention requires a reason")
        raw_conclusions = model_output["conclusions"]
        if not isinstance(raw_conclusions, list) or len(raw_conclusions) > 50:
            raise ValueError("invalid conclusions")
        conclusions: list[SecurityConclusion] = []
        known = set(request.evidence_ids)
        for raw in raw_conclusions:
            if type(raw) is not dict or set(raw) != {"text", "evidence_ids"}:
                raise ValueError("conclusion must use the exact object schema")
            text = raw["text"]
            raw_citations = raw["evidence_ids"]
            if not isinstance(text, str):
                raise ValueError("invalid conclusion text")
            if (
                not isinstance(raw_citations, list)
                or len(raw_citations) > MAX_EVIDENCE_IDS
                or any(
                    not isinstance(value, str) or not value or len(value) > 256
                    for value in raw_citations
                )
            ):
                raise ValueError("invalid conclusion evidence citations")
            citations = tuple(raw_citations)
            if not text or len(text) > 4000:
                raise ValueError("invalid conclusion text")
            if not citations:
                raise ValueError("security conclusions require evidence citations")
            if len(citations) != len(set(citations)):
                raise ValueError("duplicate conclusion evidence citation")
            if not set(citations) <= known:
                raise ValueError("conclusion cites unknown evidence")
            conclusions.append(SecurityConclusion(text, citations))
        if not abstained and not conclusions:
            raise ValueError("non-abstaining output requires a cited conclusion")

        tool_name = model_output.get("tool_name", "")
        raw_args = model_output.get("tool_arguments", {})
        if abstained and tool_name:
            raise ValueError("an abstaining model cannot request a tool")
        arguments: tuple[tuple[str, Any], ...] = ()
        if request.mode is AIMode.EXECUTE:
            if abstained:
                if tool_name or raw_args:
                    raise ValueError("an abstaining model cannot request a tool")
                tool_name = ""
            elif not isinstance(tool_name, str) or tool_name not in self._tools:
                raise ValueError("execute mode requires a registered typed tool")
            if abstained:
                raw_args = {}
            elif type(raw_args) is not dict:
                raise ValueError("tool arguments must be a plain JSON object")
            if abstained:
                tool = None
            else:
                tool = self._tools[tool_name]
            if tool is None:
                validated = {}
            else:
                if set(raw_args) != set(tool.validators):
                    raise ValueError("tool argument names do not match its schema")
                try:
                    validated = {
                        name: validator(raw_args[name])
                        for name, validator in tool.validators.items()
                    }
                except Exception as exc:
                    raise ValueError("tool argument validation failed") from exc
            if len(_canonical_json(validated)) > MAX_OUTPUT_CHARS:
                raise ValueError("validated tool arguments exceed the bound")
            arguments = tuple(sorted(validated.items()))
        response = BrokerResponse(
            request_id=request.request_id,
            mode=request.mode,
            conclusions=tuple(conclusions),
            confidence=confidence,
            abstained=abstained,
            abstention_reason=reason,
            tool_name=tool_name,
            tool_arguments=arguments,
        )
        stamp = float(self._clock())
        if not math.isfinite(stamp):
            raise ValueError("AI broker clock is invalid")
        response = replace(
            response,
            authorized_at=stamp,
            expires_at=(stamp + self._execution_ttl if request.mode is AIMode.EXECUTE else 0),
        )
        response = replace(
            response,
            authorization_tag=self._authorization_tag(response),
        )
        return response

    def execute(self, response: BrokerResponse) -> BrokerResponse:
        if not isinstance(response, BrokerResponse) or response.mode is not AIMode.EXECUTE:
            raise ValueError("response is not an execution request")
        if not self.execution_enabled:
            raise PermissionError("AI tool execution is disabled")
        if response.tool_executed or response.tool_result is not None:
            raise PermissionError("AI tool response has already been executed")
        tool = self._tools.get(response.tool_name)
        if tool is None:
            raise ValueError("tool is no longer registered")
        stamp = float(self._clock())
        if (
            not math.isfinite(stamp)
            or type(response.authorized_at) not in (int, float)
            or type(response.expires_at) not in (int, float)
            or not math.isfinite(response.authorized_at)
            or not math.isfinite(response.expires_at)
            or response.authorized_at <= 0
            or response.expires_at <= response.authorized_at
            or stamp > response.expires_at
        ):
            raise PermissionError("AI tool authorization is expired or invalid")
        expected = self._authorization_tag(response)
        if not re.fullmatch(r"[0-9a-f]{64}", response.authorization_tag) or not hmac.compare_digest(
            response.authorization_tag, expected
        ):
            raise PermissionError("AI tool response was not authorized by this broker")
        with self._execution_lock:
            expired = [tag for tag, expires in self._consumed.items() if expires < stamp]
            for tag in expired:
                self._consumed.pop(tag, None)
            if response.authorization_tag in self._consumed:
                raise PermissionError("AI tool authorization was already consumed")
            if len(self._consumed) >= MAX_PENDING_EXECUTIONS:
                raise PermissionError("AI tool replay ledger is at capacity")
            # Consume before entering plugin/tool code. A failing handler cannot
            # turn the same model-issued capability into an execution replay.
            self._consumed[response.authorization_tag] = response.expires_at
        result = tool.handler(**dict(response.tool_arguments))
        if len(_canonical_json(result)) > MAX_TOOL_RESULT_CHARS:
            raise ValueError("AI tool result exceeds the bound")
        executed = replace(
            response,
            authorization_tag="",
            tool_executed=True,
            tool_result=result,
        )
        return replace(
            executed,
            authorization_tag=self._authorization_tag(executed),
        )

    def receipt(
        self,
        request: AIRequest,
        response: BrokerResponse,
        *,
        accepted: bool = True,
        now: float | None = None,
    ) -> AuditReceipt:
        if (
            not isinstance(request, AIRequest)
            or not isinstance(response, BrokerResponse)
            or type(accepted) is not bool
            or response.request_id != request.request_id
            or response.mode is not request.mode
            or not re.fullmatch(r"[0-9a-f]{64}", response.authorization_tag)
            or not hmac.compare_digest(
                response.authorization_tag,
                self._authorization_tag(response),
            )
        ):
            raise PermissionError("AI audit receipt requires this broker's validated response")
        request_hash = hashlib.sha256(request.canonical()).hexdigest()
        response_hash = self._canonical_hash(asdict(response))
        created = time.time() if now is None else float(now)
        if not math.isfinite(created):
            raise ValueError("AI audit receipt time must be finite")
        core = {
            "request_id": request.request_id,
            "request_hash": request_hash,
            "response_hash": response_hash,
            "mode": request.mode.value,
            "provider": request.provenance.provider,
            "model": request.provenance.model,
            "version": request.provenance.version,
            "local": request.provenance.local,
            "accepted": accepted,
            "tool_name": response.tool_name,
            "tool_executed": response.tool_executed,
            "created_at": created,
        }
        receipt_hash = hmac.new(self._audit_key, _canonical_json(core), hashlib.sha256).hexdigest()
        return AuditReceipt(**core, receipt_hash=receipt_hash)

    def verify_receipt(self, receipt: AuditReceipt) -> bool:
        if not isinstance(receipt, AuditReceipt):
            return False
        try:
            core = asdict(receipt)
            supplied = core.pop("receipt_hash", "")
            expected = hmac.new(self._audit_key, _canonical_json(core), hashlib.sha256).hexdigest()
            return (
                isinstance(supplied, str)
                and bool(re.fullmatch(r"[0-9a-f]{64}", supplied))
                and hmac.compare_digest(supplied, expected)
            )
        except Exception:
            return False
