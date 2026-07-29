"""Local-first policy boundary for untrusted AI security output.

No model or network client exists here. Callers supply model output as data,
which is validated before it can become a recommendation, plan, or typed tool
invocation.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Callable, Mapping

MAX_INPUT_CHARS = 32_000
MAX_OUTPUT_CHARS = 64_000
MAX_EVIDENCE_IDS = 128
MAX_TOOL_ARGUMENTS = 32


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
        if not all((self.provider, self.model, self.version)):
            raise ValueError("complete model provenance is required")


@dataclass(frozen=True)
class EgressDecision:
    cloud_allowed: bool = False
    operator_approved: bool = False
    reason: str = "local-only default"

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
        object.__setattr__(self, "evidence_ids", tuple(self.evidence_ids))
        if not self.request_id or len(self.request_id) > 128:
            raise ValueError("invalid request ID")
        if not self.prompt or len(self.prompt) > MAX_INPUT_CHARS:
            raise ValueError("input is empty or exceeds the bound")
        if len(self.evidence_ids) > MAX_EVIDENCE_IDS:
            raise ValueError("too many evidence IDs")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("duplicate evidence ID")
        if not self.egress.permits(self.provenance):
            raise ValueError("model provenance is not permitted by egress decision")

    def canonical(self) -> bytes:
        return json.dumps(
            asdict(self), sort_keys=True, separators=(",", ":"), default=str
        ).encode("utf-8")


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


class AISecurityBroker:
    def __init__(self, *, execution_enabled: bool = False) -> None:
        self.execution_enabled = bool(execution_enabled)
        self._tools: dict[str, _Tool] = {}

    def register_tool(
        self,
        name: str,
        *,
        validators: Mapping[str, Callable[[Any], Any]],
        handler: Callable[..., Any],
    ) -> None:
        if not name or name in self._tools:
            raise ValueError("tool name must be non-empty and unique")
        if any(token in name.casefold() for token in ("shell", "powershell", "cmd", "code")):
            raise ValueError("raw shell/code tools are forbidden")
        if not validators or len(validators) > MAX_TOOL_ARGUMENTS:
            raise ValueError("typed tool validators are required")
        self._tools[name] = _Tool(dict(validators), handler)

    @staticmethod
    def _canonical_hash(value: Any) -> str:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), default=str
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def validate(
        self, request: AIRequest, model_output: Mapping[str, Any]
    ) -> BrokerResponse:
        encoded = json.dumps(model_output, default=str)
        if len(encoded) > MAX_OUTPUT_CHARS:
            raise ValueError("model output exceeds the bound")
        confidence = model_output.get("confidence")
        if type(confidence) is not int or not 0 <= confidence <= 100:
            raise ValueError("confidence must be an integer from 0 to 100")
        abstained = model_output.get("abstained")
        if type(abstained) is not bool:
            raise ValueError("explicit abstention state is required")
        reason = str(model_output.get("abstention_reason", ""))
        if abstained and not reason:
            raise ValueError("abstention requires a reason")
        raw_conclusions = model_output.get("conclusions", [])
        if not isinstance(raw_conclusions, list) or len(raw_conclusions) > 50:
            raise ValueError("invalid conclusions")
        conclusions: list[SecurityConclusion] = []
        known = set(request.evidence_ids)
        for raw in raw_conclusions:
            if not isinstance(raw, Mapping):
                raise ValueError("conclusion must be an object")
            text = str(raw.get("text", ""))
            citations = tuple(raw.get("evidence_ids", ()))
            if not text or len(text) > 4000:
                raise ValueError("invalid conclusion text")
            if not citations:
                raise ValueError("security conclusions require evidence citations")
            if not set(citations) <= known:
                raise ValueError("conclusion cites unknown evidence")
            conclusions.append(SecurityConclusion(text, citations))
        if not abstained and not conclusions:
            raise ValueError("non-abstaining output requires a cited conclusion")

        tool_name = str(model_output.get("tool_name", ""))
        raw_args = model_output.get("tool_arguments", {})
        if request.mode is not AIMode.EXECUTE and (tool_name or raw_args):
            raise ValueError("tools are allowed only in execute mode")
        if abstained and tool_name:
            raise ValueError("an abstaining model cannot request a tool")
        arguments: tuple[tuple[str, Any], ...] = ()
        if request.mode is AIMode.EXECUTE:
            if not tool_name or tool_name not in self._tools:
                raise ValueError("execute mode requires a registered typed tool")
            if not isinstance(raw_args, Mapping):
                raise ValueError("tool arguments must be an object")
            tool = self._tools[tool_name]
            if set(raw_args) != set(tool.validators):
                raise ValueError("tool argument names do not match its schema")
            validated = {
                name: validator(raw_args[name])
                for name, validator in tool.validators.items()
            }
            arguments = tuple(sorted(validated.items()))
        return BrokerResponse(
            request.request_id, request.mode, tuple(conclusions), confidence,
            abstained, reason, tool_name, arguments,
        )

    def execute(self, response: BrokerResponse) -> BrokerResponse:
        if response.mode is not AIMode.EXECUTE:
            raise ValueError("response is not an execution request")
        if not self.execution_enabled:
            raise PermissionError("AI tool execution is disabled")
        tool = self._tools.get(response.tool_name)
        if tool is None:
            raise ValueError("tool is no longer registered")
        result = tool.handler(**dict(response.tool_arguments))
        return BrokerResponse(
            response.request_id, response.mode, response.conclusions,
            response.confidence, response.abstained, response.abstention_reason,
            response.tool_name, response.tool_arguments, True, result,
        )

    def receipt(
        self, request: AIRequest, response: BrokerResponse, *, accepted: bool = True,
        now: float | None = None,
    ) -> AuditReceipt:
        request_hash = hashlib.sha256(request.canonical()).hexdigest()
        response_hash = self._canonical_hash(asdict(response))
        created = time.time() if now is None else float(now)
        core = {
            "request_id": request.request_id, "request_hash": request_hash,
            "response_hash": response_hash, "mode": request.mode.value,
            "provider": request.provenance.provider,
            "model": request.provenance.model,
            "version": request.provenance.version,
            "local": request.provenance.local, "accepted": bool(accepted),
            "tool_name": response.tool_name,
            "tool_executed": response.tool_executed, "created_at": created,
        }
        return AuditReceipt(**core, receipt_hash=self._canonical_hash(core))
