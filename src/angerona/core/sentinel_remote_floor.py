"""Remote, signed response continuity for an independently enrolled Sentinel.

No counter or checkpoint is stored on the monitored host. The floor is kept by
an independently administered authority outside that host's snapshot boundary.
This does not protect a rollback of the authority's own entire storage; that
requires the authority's separate generation floor or equivalent custody.
"""
from __future__ import annotations

import secrets
import threading
import time
from typing import Callable

from .independent_high_water import HighWaterRejected, HighWaterUnavailable, validate_installation_id
from .personal_sentinel_authority import (
    MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, REQUEST_SCHEMA, RESPONSE_SCHEMA,
    TRANSPORT_RESPONSE_FLOOR_NAMESPACE, TRUSTED_TIME_APPRAISAL_FLOOR_NAMESPACE,
    Ed25519PrivateSigner, Ed25519PublicVerifier, PinnedHttpsSentinelTransport,
    SentinelRequestRejected, SentinelTransportResult, _NONCE, _RESPONSE_KEYS,
    _canonical, _client_instance_id, _finite_time, _sign, _signature, _strict_json,
    require_independent_ed25519_enrollment,
)

FLOOR_OPERATION = "client-floor-advance"
FLOOR_STATE_FIELD = "client_response_floors"
FLOOR_NAMESPACES = frozenset({
    TRANSPORT_RESPONSE_FLOOR_NAMESPACE, TRUSTED_TIME_APPRAISAL_FLOOR_NAMESPACE,
})
_FLOOR_KEYS = frozenset({
    "namespace", "installation_id", "client_instance_id", "sequence", "received_at",
})


def parse_floor_tuple(value, *, installation_id: str, client_instance_id: str) -> dict:
    """Validate the complete durable floor identity; never collapse namespaces."""
    if (type(value) is not dict or set(value) != _FLOOR_KEYS
            or value.get("namespace") not in FLOOR_NAMESPACES
            or value.get("installation_id") != installation_id
            or value.get("client_instance_id") != client_instance_id
            or type(value.get("sequence")) is not int
            or not 1 <= value["sequence"] <= 2**63 - 1):
        raise SentinelRequestRejected("Client response floor tuple is invalid")
    received = _finite_time(value["received_at"], "client floor receipt time")
    return {**value, "received_at": received}


def validate_floor_state(value, *, installation_id: str, client_instance_id: str) -> list[dict]:
    if type(value) is not list or not 1 <= len(value) <= len(FLOOR_NAMESPACES):
        raise SentinelRequestRejected("Client response floor state is invalid")
    rows = [parse_floor_tuple(row, installation_id=installation_id,
                              client_instance_id=client_instance_id) for row in value]
    if len({row["namespace"] for row in rows}) != len(rows):
        raise SentinelRequestRejected("Client response floor namespaces are duplicated")
    return rows


def advance_floor_state(state: dict, proposal: dict, *, installation_id: str,
                        client_instance_id: str) -> bool:
    """Called only under the authority's authenticated state transaction/lease."""
    candidate = parse_floor_tuple(proposal, installation_id=installation_id,
                                 client_instance_id=client_instance_id)
    rows = state.get(FLOOR_STATE_FIELD, [])
    if rows:
        rows = validate_floor_state(rows, installation_id=installation_id,
                                    client_instance_id=client_instance_id)
    current = next((row for row in rows if row["namespace"] == candidate["namespace"]), None)
    if current is not None and (candidate["sequence"] <= current["sequence"]
                                or candidate["received_at"] < current["received_at"]):
        return False
    state[FLOOR_STATE_FIELD] = sorted(
        [row for row in rows if row["namespace"] != candidate["namespace"]] + [candidate],
        key=lambda row: row["namespace"],
    )
    return True


class RawSignedFloorClient:
    """Existing SentinelResponseFloor API over direct nonce-bound signed HTTPS.

    No PersonalSentinelAuthorityClient is used, including indirectly: a floor
    request must not recursively ask another response floor to validate itself.
    Production enrollment asserts external physical/administrative custody;
    software cannot prove that an operator chose a different physical host.
    """

    def __init__(self, *, installation_id: str, client_instance_id: str,
                 request_signer: Ed25519PrivateSigner,
                 response_verifier: Ed25519PublicVerifier, transport,
                 independently_administered: bool = False,
                 clock: Callable[[], float] = time.time,
                 nonce_factory: Callable[[], str] | None = None,
                 max_response_age: float = 60.0, allow_test_transport: bool = False):
        self.installation_id = validate_installation_id(installation_id)
        self.client_instance_id = _client_instance_id(client_instance_id)
        if type(request_signer) is not Ed25519PrivateSigner:
            raise ValueError("Remote floor requires an exact Ed25519 request signer")
        require_independent_ed25519_enrollment(
            request_verifier=request_signer.public_verifier(),
            response_verifier=response_verifier,
        )
        if type(allow_test_transport) is not bool or type(independently_administered) is not bool:
            raise ValueError("Remote floor mode must be explicitly boolean")
        if not allow_test_transport and (type(transport) is not PinnedHttpsSentinelTransport
                                         or independently_administered is not True):
            raise ValueError("Remote floor requires enrolled pinned HTTPS and independent administration")
        if (isinstance(max_response_age, bool) or not isinstance(max_response_age, (float, int))
                or not 1.0 <= float(max_response_age) <= 300.0):
            raise ValueError("Remote floor response freshness bound is invalid")
        self.request_signer, self.response_verifier, self.transport = request_signer, response_verifier, transport
        self._clock, self._nonce_factory = clock, nonce_factory or (lambda: secrets.token_urlsafe(32))
        self._max_response_age, self._test_mode = float(max_response_age), allow_test_transport
        self._lock = threading.RLock()
        self._last_sequence, self._last_received, self._last_local_time = 0, 0.0, 0.0

    def compare_and_advance(self, *, namespace: str, installation_id: str,
                            client_instance_id: str, sequence: int, received_at: float) -> bool:
        with self._lock:
            try:
                proposal = parse_floor_tuple(dict(namespace=namespace, installation_id=installation_id,
                    client_instance_id=client_instance_id, sequence=sequence, received_at=received_at),
                    installation_id=self.installation_id, client_instance_id=self.client_instance_id)
                now = _finite_time(self._clock(), "remote floor client time")
                if now < self._last_local_time:
                    raise HighWaterRejected("Remote floor client clock regressed")
                nonce = self._nonce_factory()
            except (SentinelRequestRejected, ValueError) as exc:
                raise HighWaterRejected("Remote floor proposal or clock is invalid") from exc
            if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
                raise HighWaterRejected("Remote floor nonce is invalid")
            request = dict(schema=REQUEST_SCHEMA, operation=FLOOR_OPERATION,
                installation_id=self.installation_id, client_instance_id=self.client_instance_id,
                nonce=nonce, issued_at=now, key_id=self.request_signer.key_id, payload=proposal)
            try:
                request["signature"] = _sign(self.request_signer, _canonical(request))
                body = _canonical(request)
                if len(body) > MAX_REQUEST_BYTES:
                    raise HighWaterRejected("Remote floor request exceeds its byte bound")
                exchange = self.transport.exchange(body)
            except (HighWaterRejected, HighWaterUnavailable):
                raise
            except SentinelRequestRejected as exc:
                raise HighWaterRejected("Remote floor authority rejected the request") from exc
            except Exception as exc:
                raise HighWaterUnavailable("Remote floor signing or transport is unavailable") from exc
            if (type(exchange) is not SentinelTransportResult
                    or (self._test_mode and (exchange.test_only is not True or exchange.tls_verified is not False))
                    or (not self._test_mode and (exchange.test_only is not False or exchange.tls_verified is not True))):
                raise HighWaterRejected("Remote floor transport mode is invalid")
            try:
                response = _strict_json(exchange.body, maximum=MAX_RESPONSE_BYTES, exact_keys=_RESPONSE_KEYS)
                if (response.get("schema") != RESPONSE_SCHEMA or response.get("operation") != FLOOR_OPERATION
                        or response.get("request_nonce") != nonce or response.get("status") != "ok"
                        or response.get("key_id") != self.response_verifier.key_id):
                    raise HighWaterRejected("Remote floor response identity is invalid")
                signature = _signature(response["signature"])
                if self.response_verifier.verify(_canonical({k: v for k, v in response.items()
                                                           if k != "signature"}), signature) is not True:
                    raise HighWaterRejected("Remote floor response signature is invalid")
                finished = _finite_time(self._clock(), "remote floor completion time")
                received = _finite_time(response["received_at"], "remote floor receipt time")
                expires = _finite_time(response["expires_at"], "remote floor expiry")
                reply_sequence = response["sequence"]
                if (finished < now or received > finished + self._max_response_age
                        or finished - received > self._max_response_age or expires <= received
                        or expires < finished or expires - received > 300.0
                        or type(reply_sequence) is not int or not 1 <= reply_sequence <= 2**63 - 1
                        or reply_sequence <= self._last_sequence or received < self._last_received):
                    raise HighWaterRejected("Remote floor response is stale, replayed or regressed")
                acknowledgement = response["payload"]
                if (type(acknowledgement) is not dict or set(acknowledgement) != _FLOOR_KEYS | {"advanced"}
                        or type(acknowledgement["advanced"]) is not bool
                        or parse_floor_tuple({k: v for k, v in acknowledgement.items() if k != "advanced"},
                            installation_id=self.installation_id,
                            client_instance_id=self.client_instance_id) != proposal):
                    raise HighWaterRejected("Remote floor acknowledgement does not match the proposal")
            except SentinelRequestRejected as exc:
                raise HighWaterRejected("Remote floor response schema is invalid") from exc
            self._last_sequence, self._last_received, self._last_local_time = reply_sequence, received, finished
            return acknowledgement["advanced"]
