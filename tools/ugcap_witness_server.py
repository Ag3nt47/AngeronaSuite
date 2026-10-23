#!/usr/bin/env python
"""Explicitly deploy the UGCAP witness on a separately administered private host.

Requires private mTLS and separately provisioned Ed25519 roles and fixed vault
enrollment. No endpoint resets a head, enrolls a supplied key, or runs commands.
An unchanged remote witness detects host-disk rollback; restoring this witness's
entire signed disk state still needs a separate hardware/independent floor.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler
from pathlib import Path
import ssl
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT, ROOT / "src"):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from angerona.core.ugcap_witness import (  # noqa: E402
    MAX_BYTES, WitnessAuthority, WitnessError, _hex, _path_chain,
)
from angerona.core.engine_transport import verify_private  # noqa: E402
from tools.personal_sentinel_server import (  # noqa: E402
    _BoundedThreadingHTTPServer, _identity, _load_pem, _private_bind,
)


def _protected_path(path, *, may_be_absent=False):
    """Require the dedicated witness account's private, non-aliased custody.

    This service does not need an elevated account. Admin/SYSTEM remain trusted
    local actors; do not mix the admin-owned Sentinel profile with this separate
    current-user-owned service profile.
    """
    path = path.expanduser().absolute()
    _path_chain(path)
    verify_private(path.parent, directory=True)
    if not may_be_absent or path.exists():
        verify_private(path)
    return path


def handler_for(authority, *, request_timeout=6.0):
    if type(request_timeout) not in (int, float) or not .25 <= request_timeout <= 6.0:
        raise ValueError("invalid bounded request deadline")
    class DeadlineReader:
        """One bounded HTTP request, including slow-drip headers and body."""
        def __init__(self, source, connection):
            self.source, self.connection = source, connection
            self.pending = bytearray()
            self.deadline = time.monotonic() + request_timeout
            self.received = 0

        def _fill(self):
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise WitnessError("request-deadline")
            self.connection.settimeout(min(3.0, remaining))
            block = self.source.read1(4096)
            self.received += len(block)
            if not block or self.received > MAX_BYTES + 8192:
                raise WitnessError("request-truncated-or-oversized")
            self.pending.extend(block)

        def read(self, count):
            output = bytearray()
            while len(output) < count:
                if not self.pending:
                    self._fill()
                take = min(count - len(output), len(self.pending))
                output.extend(self.pending[:take])
                del self.pending[:take]
            return bytes(output)

        def readline(self, limit):
            output = bytearray()
            while len(output) < limit:
                if not self.pending:
                    self._fill()
                end = self.pending.find(b"\n")
                take = min(limit - len(output), end + 1 if end >= 0 else len(self.pending))
                output.extend(self.pending[:take])
                del self.pending[:take]
                if output.endswith(b"\n"):
                    break
            return bytes(output)

        def close(self):
            self.source.close()

    class Handler(BaseHTTPRequestHandler):
        server_version = "AngeronaWitness/1"
        sys_version = ""

        def setup(self):
            super().setup()
            self.request.settimeout(3.0)
            self.rfile = DeadlineReader(self.rfile, self.request)

        def handle(self):
            try:
                super().handle()
            except (OSError, WitnessError):
                self.close_connection = True

        def log_message(self, *_args):
            pass

        def _reply(self, status, body):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def do_POST(self):  # noqa: N802
            lengths = self.headers.get_all("Content-Length", [])
            if (self.path != "/v1/ugcap-witness" or len(self.headers) > 32
                    or self.headers.get("Transfer-Encoding") is not None
                    or len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit()
                    or len(lengths[0]) > 6
                    or self.headers.get("Content-Type", "").casefold() != "application/json"):
                self._reply(400, b'{"error":"request-rejected"}')
                return
            size = int(lengths[0])
            if not 1 <= size <= MAX_BYTES:
                self._reply(413, b'{"error":"size-rejected"}')
                return
            try:
                body = self.rfile.read(size)
                if len(body) != size:
                    raise WitnessError("truncated")
                response = authority.process(body)
            except Exception:
                self._reply(403, b'{"error":"witness-rejected"}')
                return
            self._reply(200, response)

    return Handler


WitnessHTTPServer = _BoundedThreadingHTTPServer


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", type=_private_bind, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9444)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--initialize", action="store_true",
                        help="explicit first enrollment only; refuses any existing state or enrollment marker")
    parser.add_argument("--installation-id", type=_identity, required=True)
    parser.add_argument("--client-id", type=_identity, required=True)
    parser.add_argument("--vault-id", type=_identity, required=True)
    parser.add_argument("--baseline-id", required=True)
    parser.add_argument("--client-public-key-file", type=Path, required=True)
    parser.add_argument("--authority-private-key-file", type=Path, required=True)
    parser.add_argument("--tls-cert", type=Path, required=True)
    parser.add_argument("--tls-key", type=Path, required=True)
    parser.add_argument("--client-ca", type=Path, required=True)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("invalid port")
    authority = None
    server = None
    try:
        _hex(args.baseline_id, 64)
        for name in ("client_public_key_file", "authority_private_key_file", "tls_cert", "tls_key", "client_ca"):
            setattr(args, name, _protected_path(getattr(args, name)))
        args.state = _protected_path(args.state, may_be_absent=True)
        authority = WitnessAuthority(args.state, installation_id=args.installation_id,
            client_id=args.client_id, vault_id=args.vault_id, baseline_id=args.baseline_id,
            initialize=args.initialize,
            client_verifier=_load_pem(args.client_public_key_file, private=False, key_id="ugcap-witness-host-v1"),
            signer=_load_pem(args.authority_private_key_file, private=True, key_id="ugcap-witness-authority-v1"))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(args.tls_cert), str(args.tls_key))
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=str(args.client_ca))
        server = WitnessHTTPServer((args.bind, args.port), handler_for(authority), tls_context=context)
        print("UGCAP witness ready. Host rollback comparison requires this separately retained state; "
              "whole witness snapshot rollback and a hostile signing host remain outside this proof.", flush=True)
        server.serve_forever(poll_interval=.25)
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        parser.error("witness setup or service failed: " + type(exc).__name__)
    finally:
        if server is not None:
            server.server_close()
        if authority is not None:
            authority.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
