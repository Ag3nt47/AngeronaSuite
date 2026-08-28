"""Inert-by-default contract for a privilege-separated local service.

There is no listener, subprocess launcher, shell, or implicit transport here.
The embedding application must inject both a narrowly typed executor and a
transport.  Requests and responses use exact canonical JSON schemas protected
by a transport HMAC; execution additionally requires a single-use capability
from :mod:`angerona.core.response_capability`.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
from dataclasses import dataclass
from typing import Mapping, Protocol

from .response_capability import (
    CapabilityError,
    PrivilegedOpcode,
    ResponseCapabilityAuthority,
    canonicalize_parameters,
)


REQUEST_FORMAT = "angerona-privileged-request-v1"
RESPONSE_FORMAT = "angerona-privileged-response-v1"
MAX_REQUEST_BYTES = 32 * 1024
MAX_RESPONSE_BYTES = 32 * 1024
MAX_RESULT_ITEMS = 128
MAX_RESULT_DEPTH = 6
_REQUEST_FIELDS = frozenset(
    {"format", "request_id", "opcode", "resource", "parameters", "capability"}
)
_RESPONSE_FIELDS = frozenset({"format", "request_id", "opcode", "result"})
_WRAPPER_FIELDS = frozenset({"payload", "hmac_sha256"})
_REQUEST_ID = re.compile(r"^[0-9a-f]{32}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_REQUEST_DOMAIN = b"Angerona-Privileged-Request-v1\x00"
_RESPONSE_DOMAIN = b"Angerona-Privileged-Response-v1\x00"


class PrivilegedServiceError(RuntimeError):
    """A service request failed closed before or during privileged execution."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class PrivilegedExecutor(Protocol):
    """Closed executor boundary; implementations receive an enum, never argv."""

    def execute(
        self,
        opcode: PrivilegedOpcode,
        resource: str,
        parameters: Mapping[str, object],
    ) -> Mapping[str, object]: ...


class PrivilegedTransport(Protocol):
    """Injected local transport; this package does not create a listener."""

    def exchange(self, envelope: Mapping[str, object]) -> object: ...


@dataclass(frozen=True)
class ServiceHealth:
    state: str
    reason: str


@dataclass(frozen=True)
class PrivilegedExecutionResult:
    request_id: str
    opcode: PrivilegedOpcode
    result: Mapping[str, object]


def _transport_key(value: bytes | None) -> bytes | None:
    if value is None:
        return None
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("privileged transport key must be bytes")
    result = bytes(value)
    if len(result) < 32:
        raise ValueError("privileged transport key must contain at least 32 bytes")
    return result


def _canonical(value: object, *, code: str = "schema") -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PrivilegedServiceError(code, "privileged envelope is not canonical JSON") from exc


def _decode(document: object, *, limit: int) -> Mapping[str, object]:
    if isinstance(document, Mapping):
        if len(_canonical(document)) > limit:
            raise PrivilegedServiceError("bounds", "privileged envelope exceeds its byte bound")
        return document
    if isinstance(document, str):
        raw = document.encode("utf-8")
    elif isinstance(document, (bytes, bytearray, memoryview)):
        raw = bytes(document)
    else:
        raise PrivilegedServiceError("schema", "privileged envelope must be JSON or a mapping")
    if len(raw) > limit:
        raise PrivilegedServiceError("bounds", "privileged envelope exceeds its byte bound")

    def unique_object(pairs):
        output = {}
        for key, value in pairs:
            if key in output:
                raise PrivilegedServiceError("schema", "privileged envelope has duplicate fields")
            output[key] = value
        return output

    try:
        result = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PrivilegedServiceError("schema", "privileged envelope is not strict JSON") from exc
    if not isinstance(result, Mapping):
        raise PrivilegedServiceError("schema", "privileged wrapper must be an object")
    return result


def _request_id(value: object) -> str:
    if not isinstance(value, str) or not _REQUEST_ID.fullmatch(value):
        raise PrivilegedServiceError("schema", "privileged request identity is invalid")
    return value


def _operation(value: object) -> PrivilegedOpcode:
    if not isinstance(value, str):
        raise PrivilegedServiceError("opcode", "privileged opcode is invalid")
    try:
        return PrivilegedOpcode(value)
    except ValueError as exc:
        raise PrivilegedServiceError("opcode", "privileged opcode is not in the closed catalog") from exc


def _sign(payload: Mapping[str, object], key: bytes, domain: bytes) -> dict[str, object]:
    signature = hmac.new(key, domain + _canonical(payload), hashlib.sha256).hexdigest()
    return {"payload": dict(payload), "hmac_sha256": signature}


def _verify_wrapper(
    document: object,
    *,
    key: bytes,
    domain: bytes,
    limit: int,
) -> Mapping[str, object]:
    wrapper = _decode(document, limit=limit)
    if frozenset(wrapper) != _WRAPPER_FIELDS:
        raise PrivilegedServiceError("schema", "privileged wrapper fields do not match v1")
    payload = wrapper.get("payload")
    signature = wrapper.get("hmac_sha256")
    if not isinstance(payload, Mapping):
        raise PrivilegedServiceError("schema", "privileged payload must be an object")
    if not isinstance(signature, str) or not _DIGEST.fullmatch(signature):
        raise PrivilegedServiceError("authentication", "privileged envelope HMAC is invalid")
    expected = hmac.new(key, domain + _canonical(payload), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise PrivilegedServiceError("authentication", "privileged envelope HMAC failed")
    return payload


def build_privileged_request(
    transport_key: bytes,
    *,
    request_id: str,
    capability: Mapping[str, object],
    opcode: PrivilegedOpcode,
    resource: str,
    parameters: Mapping[str, object],
) -> dict[str, object]:
    """Build one canonical authenticated request for an injected transport."""
    key = _transport_key(transport_key)
    if key is None:
        raise PrivilegedServiceError("unconfigured", "privileged transport key is absent")
    identity = _request_id(request_id)
    if not isinstance(opcode, PrivilegedOpcode):
        raise PrivilegedServiceError("opcode", "a closed PrivilegedOpcode is required")
    normalized, _encoded = canonicalize_parameters(parameters)
    if not isinstance(capability, Mapping):
        raise PrivilegedServiceError("schema", "privileged capability must be an object")
    payload = {
        "format": REQUEST_FORMAT,
        "request_id": identity,
        "opcode": opcode.value,
        "resource": resource,
        "parameters": normalized,
        "capability": dict(capability),
    }
    envelope = _sign(payload, key, _REQUEST_DOMAIN)
    if len(_canonical(envelope)) > MAX_REQUEST_BYTES:
        raise PrivilegedServiceError("bounds", "privileged request exceeds its byte bound")
    return envelope


class PrivilegedService:
    """Validate, burn a capability, then call one explicitly injected executor."""

    def __init__(
        self,
        capabilities: ResponseCapabilityAuthority | None = None,
        *,
        transport_key: bytes | None = None,
        executor: PrivilegedExecutor | None = None,
    ) -> None:
        if capabilities is not None and not isinstance(capabilities, ResponseCapabilityAuthority):
            raise TypeError("privileged service requires a ResponseCapabilityAuthority")
        self._capabilities = capabilities
        self._transport_key = _transport_key(transport_key)
        self._executor = executor
        self._degraded_reason = ""
        self._lock = threading.RLock()

    def health(self) -> ServiceHealth:
        if self._capabilities is None and self._transport_key is None and self._executor is None:
            return ServiceHealth("unconfigured", "service-components-not-injected")
        missing = []
        if self._capabilities is None:
            missing.append("capability-authority")
        elif self._capabilities.health().state != "ready":
            return ServiceHealth("degraded", "capability-authority-not-ready")
        if self._transport_key is None:
            missing.append("transport-key")
        if self._executor is None:
            missing.append("executor")
        if missing:
            return ServiceHealth("degraded", "missing-" + ",".join(missing))
        if self._degraded_reason:
            return ServiceHealth("degraded", self._degraded_reason)
        return ServiceHealth("ready", "privileged-service-ready")

    def handle(self, document: object) -> dict[str, object]:
        """Handle one local envelope; no listener is created by this class."""
        health = self.health()
        if health.state != "ready":
            raise PrivilegedServiceError(health.state, health.reason)
        assert self._transport_key is not None
        assert self._capabilities is not None
        assert self._executor is not None
        payload = _verify_wrapper(
            document,
            key=self._transport_key,
            domain=_REQUEST_DOMAIN,
            limit=MAX_REQUEST_BYTES,
        )
        if frozenset(payload) != _REQUEST_FIELDS or payload.get("format") != REQUEST_FORMAT:
            raise PrivilegedServiceError("schema", "privileged request fields do not match v1")
        identity = _request_id(payload.get("request_id"))
        operation = _operation(payload.get("opcode"))
        resource = payload.get("resource")
        if not isinstance(resource, str):
            raise PrivilegedServiceError("resource", "privileged resource is invalid")
        try:
            parameters, _encoded = canonicalize_parameters(payload.get("parameters"))
            capability = payload.get("capability")
        except CapabilityError as exc:
            raise PrivilegedServiceError(f"capability-{exc.code}", str(exc)) from exc

        # Capability consumption and execution share one lock.  Two valid
        # operations therefore cannot be burned in one order and run in
        # another, and a failure degrades the service before queued work runs.
        # The capability remains burned if execution itself fails.
        with self._lock:
            current = self.health()
            if current.state != "ready":
                raise PrivilegedServiceError(current.state, current.reason)
            try:
                self._capabilities.consume(
                    capability,
                    opcode=operation,
                    resource=resource,
                    parameters=parameters,
                )
            except CapabilityError as exc:
                raise PrivilegedServiceError(f"capability-{exc.code}", str(exc)) from exc
            try:
                result = self._executor.execute(operation, resource, dict(parameters))
                normalized_result, _encoded_result = canonicalize_parameters(result)
            except Exception as exc:
                self._degraded_reason = "executor-failure"
                raise PrivilegedServiceError("execution", "privileged executor failed") from exc
            response_payload = {
                "format": RESPONSE_FORMAT,
                "request_id": identity,
                "opcode": operation.value,
                "result": normalized_result,
            }
            response = _sign(response_payload, self._transport_key, _RESPONSE_DOMAIN)
            if len(_canonical(response)) > MAX_RESPONSE_BYTES:
                self._degraded_reason = "response-bound-exceeded"
                raise PrivilegedServiceError("bounds", "privileged response exceeds its byte bound")
            return response


class PrivilegedServiceClient:
    """Client facade that remains inert until key and transport are injected."""

    def __init__(
        self,
        *,
        transport_key: bytes | None = None,
        transport: PrivilegedTransport | None = None,
    ) -> None:
        self._transport_key = _transport_key(transport_key)
        self._transport = transport
        self._degraded_reason = ""

    def health(self) -> ServiceHealth:
        if self._transport_key is None and self._transport is None:
            return ServiceHealth("unconfigured", "client-transport-not-injected")
        if self._transport_key is None or self._transport is None:
            return ServiceHealth("degraded", "client-transport-partially-configured")
        if self._degraded_reason:
            return ServiceHealth("degraded", self._degraded_reason)
        return ServiceHealth("ready", "privileged-client-ready")

    def execute(
        self,
        *,
        request_id: str,
        capability: Mapping[str, object],
        opcode: PrivilegedOpcode,
        resource: str,
        parameters: Mapping[str, object],
    ) -> PrivilegedExecutionResult:
        health = self.health()
        if health.state != "ready":
            raise PrivilegedServiceError(health.state, health.reason)
        assert self._transport_key is not None
        assert self._transport is not None
        request = build_privileged_request(
            self._transport_key,
            request_id=request_id,
            capability=capability,
            opcode=opcode,
            resource=resource,
            parameters=parameters,
        )
        try:
            response = self._transport.exchange(request)
            payload = _verify_wrapper(
                response,
                key=self._transport_key,
                domain=_RESPONSE_DOMAIN,
                limit=MAX_RESPONSE_BYTES,
            )
        except Exception as exc:
            self._degraded_reason = "transport-or-response-failure"
            if isinstance(exc, PrivilegedServiceError):
                raise
            raise PrivilegedServiceError("transport", "privileged transport failed") from exc
        if frozenset(payload) != _RESPONSE_FIELDS or payload.get("format") != RESPONSE_FORMAT:
            self._degraded_reason = "response-schema-failure"
            raise PrivilegedServiceError("schema", "privileged response fields do not match v1")
        response_id = _request_id(payload.get("request_id"))
        response_opcode = _operation(payload.get("opcode"))
        if response_id != request_id or response_opcode is not opcode:
            self._degraded_reason = "response-binding-failure"
            raise PrivilegedServiceError("binding", "privileged response does not match request")
        try:
            result, _encoded = canonicalize_parameters(payload.get("result"))
        except CapabilityError as exc:
            self._degraded_reason = "response-schema-failure"
            raise PrivilegedServiceError("schema", str(exc)) from exc
        return PrivilegedExecutionResult(response_id, response_opcode, result)
