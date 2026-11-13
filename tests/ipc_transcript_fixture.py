"""Inert byte transports and scheduled workers: never opens sockets or threads."""
from __future__ import annotations

import struct

from angerona.core import engine_transport as transport


def frame(message):
    raw = transport.canonical(message)
    return struct.pack("!I", len(raw)) + raw


class TranscriptSocket:
    def __init__(self, incoming=b"", on_send=None):
        self.incoming = bytearray(incoming)
        self.on_send = on_send
        self.sent, self.timeouts = [], []
        self.closed = False
        self.close_calls = self.shutdown_calls = self.recv_calls = 0
        self.close_error = False

    def settimeout(self, timeout):
        assert timeout > 0
        self.timeouts.append(timeout)

    def recv(self, maximum):
        self.recv_calls += 1
        if self.closed:
            raise OSError("fixture socket retired")
        if not self.incoming:
            raise TimeoutError("fixture idle peer")
        raw = bytes(self.incoming[:maximum])
        del self.incoming[:maximum]
        return raw

    def sendall(self, raw):
        if self.closed:
            raise OSError("fixture socket retired")
        size = struct.unpack("!I", raw[:4])[0]
        assert size == len(raw) - 4
        message = transport.decode(raw[4:])
        self.sent.append(message)
        if self.on_send:
            self.on_send(self, message)

    def shutdown(self, _how):
        self.shutdown_calls += 1

    def close(self):
        self.close_calls += 1
        if self.close_error:
            raise OSError("fixture close unconfirmed")
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class InertListener(TranscriptSocket):
    def __init__(self, accepted=()):
        super().__init__()
        self.accepted = list(accepted)
        self.options, self.bound, self.backlog = [], None, None

    def setsockopt(self, *option):
        self.options.append(option)

    def bind(self, address):
        self.bound = address

    def listen(self, backlog):
        self.backlog = backlog

    def getsockname(self):
        return "127.0.0.1", 43210

    def accept(self):
        if self.closed:
            raise OSError("fixture listener retired")
        if not self.accepted:
            raise OSError("fixture accepted sequence ended")
        return self.accepted.pop(0), ("127.0.0.1", 33333)


class InertThread:
    def __init__(self, *, target, args=(), name="", daemon=False):
        self.target, self.args, self.name, self.daemon = target, args, name, daemon
        self.ident = None
        self.alive = False
        self.fail_start = False
        self.run_on_join = True
        self.joins = []
        self.current = lambda: None

    def start(self):
        if self.fail_start:
            raise RuntimeError("fixture thread start refused")
        self.ident, self.alive = 123, True

    def is_alive(self):
        return self.alive

    def run(self):
        try:
            return self.target(*self.args)
        finally:
            self.alive = False

    def join(self, timeout=None):
        self.joins.append(timeout)
        if self.alive and self.run_on_join:
            self.run()
