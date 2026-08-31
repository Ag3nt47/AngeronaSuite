"""Loopback-only, allowlisted HTTP server for Angerona's local flow canvas."""
from __future__ import annotations

import argparse
import json
import math
import os
import socket
import stat
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


LOOPBACK_HOST = "127.0.0.1"
DEFAULT_PORT = 0
MAX_CONNECTIONS = 16
HEADER_TIMEOUT_SECONDS = 2.0
MAX_METRICS_AGE_SECONDS = 120.0
MAX_FUTURE_SKEW_SECONDS = 10.0
_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_SOURCE_ROOT = _REPOSITORY_ROOT / "src"
if str(_SOURCE_ROOT) not in sys.path:
    # The direct helper is launched by exact path, so its adjacent source tree
    # is the only import root it adds. It never trusts the working directory.
    sys.path.insert(0, str(_SOURCE_ROOT))

from angerona.core.data_paths import data_dir  # noqa: E402


_RUNTIME_DATA_ROOT = data_dir(create=False)
_ALLOWED_ARTIFACTS = {
    "/flow_canvas.html": (
        "repository",
        "flow_canvas.html",
        "text/html; charset=utf-8",
        2 * 1024 * 1024,
    ),
    "/diagnostics/flow_metrics.json": (
        "runtime",
        "diagnostics/flow_metrics.json",
        "application/json; charset=utf-8",
        256 * 1024,
    ),
}
_NODE_METRICS = {
    "capture": frozenset({"Events/sec", "Queue depth", "Sensors up"}),
    "detect": frozenset({"Detectors up", "Queue depth", "Modules total"}),
    "triage": frozenset({"Audit events", "Model", "GPU tier"}),
    "respond": frozenset({"SOAR port", "Redacts", "Gate"}),
    "attack": frozenset({"Red-team up", "Mode", "Trigger"}),
    "harden": frozenset({"Threat level", "Harden mods", "Watchdog"}),
}


def _has_reparse_attribute(metadata: os.stat_result) -> bool:
    return bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _identity(metadata: os.stat_result) -> tuple[int, int]:
    return int(metadata.st_dev), int(metadata.st_ino)


def _stable_metadata(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        *_identity(metadata),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _descriptor_path(descriptor: int) -> Path | None:
    """Resolve an open file handle without reopening its pathname."""
    try:
        if sys.platform.startswith("win"):
            import ctypes
            import msvcrt
            from ctypes import wintypes

            get_final_path = ctypes.WinDLL(
                "kernel32", use_last_error=True
            ).GetFinalPathNameByHandleW
            get_final_path.argtypes = [
                wintypes.HANDLE,
                wintypes.LPWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
            ]
            get_final_path.restype = wintypes.DWORD
            handle = wintypes.HANDLE(msvcrt.get_osfhandle(descriptor))
            required = get_final_path(handle, None, 0, 0)
            if required <= 0 or required > 32_768:
                return None
            buffer = ctypes.create_unicode_buffer(required + 1)
            written = get_final_path(handle, buffer, len(buffer), 0)
            if written <= 0 or written >= len(buffer):
                return None
            final_name = buffer.value
            if final_name.startswith("\\\\?\\UNC\\"):
                final_name = "\\\\" + final_name[8:]
            elif final_name.startswith("\\\\?\\"):
                final_name = final_name[4:]
            return Path(final_name).resolve(strict=False)
        if sys.platform == "darwin":
            import fcntl

            raw_path = fcntl.fcntl(descriptor, 50, b"\0" * 1024)
            final_name = bytes(raw_path).split(b"\0", 1)[0]
            if not final_name:
                return None
            return Path(os.fsdecode(final_name)).resolve(strict=False)
        descriptor_link = Path("/proc/self/fd") / str(descriptor)
        if descriptor_link.exists():
            target = os.readlink(descriptor_link)
            if target.endswith(" (deleted)"):
                return None
            return Path(target).resolve(strict=False)
    except (OSError, TypeError, ValueError):
        return None
    return None


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(
        os.path.abspath(right)
    )


def _within_root(candidate: Path, root: Path) -> bool:
    try:
        normalized_candidate = os.path.normcase(os.path.abspath(candidate))
        normalized_root = os.path.normcase(os.path.abspath(root))
        return os.path.commonpath((normalized_candidate, normalized_root)) == (
            normalized_root
        )
    except ValueError:
        return False


def _safe_primitive(value: object) -> bool:
    if isinstance(value, bool):
        return True
    if isinstance(value, int):
        return abs(value) <= 100_000_000
    if isinstance(value, float):
        return math.isfinite(value) and abs(value) <= 100_000_000
    return isinstance(value, str) and len(value) <= 128


def _valid_metrics(payload: bytes, *, now: float | None = None) -> bool:
    """Accept only the exact, fresh, display-only canvas metrics contract."""
    try:
        document = json.loads(payload.decode("utf-8"))
        if not isinstance(document, dict) or set(document) != {
            "schema_version",
            "generated_at_epoch",
            "generated",
            "live",
            "pipeline",
            "nodes",
        }:
            return False
        generated_at = document["generated_at_epoch"]
        if (
            isinstance(generated_at, bool)
            or not isinstance(generated_at, (int, float))
            or not math.isfinite(float(generated_at))
        ):
            return False
        age = (time.time() if now is None else now) - float(generated_at)
        if age > MAX_METRICS_AGE_SECONDS or age < -MAX_FUTURE_SKEW_SECONDS:
            return False
        if (
            type(document["schema_version"]) is not int
            or document["schema_version"] != 1
            or document["live"] is not True
            or not isinstance(document["generated"], str)
            or not 1 <= len(document["generated"]) <= 40
        ):
            return False

        pipeline = document["pipeline"]
        if not isinstance(pipeline, dict) or set(pipeline) != {
            "cap_det", "det_tri", "dropped"
        }:
            return False
        for edge_name in ("cap_det", "det_tri"):
            edge = pipeline[edge_name]
            if (
                not isinstance(edge, dict)
                or set(edge) != {"queue", "latency_ms"}
                or not all(_safe_primitive(value) for value in edge.values())
            ):
                return False
        if not _safe_primitive(pipeline["dropped"]):
            return False

        nodes = document["nodes"]
        if not isinstance(nodes, dict) or set(nodes) != set(_NODE_METRICS):
            return False
        for node_id, expected_metrics in _NODE_METRICS.items():
            node = nodes[node_id]
            if not isinstance(node, dict) or set(node) != {"state", "metrics"}:
                return False
            if node["state"] not in {"ok", "err"}:
                return False
            metrics = node["metrics"]
            if (
                not isinstance(metrics, dict)
                or set(metrics) != set(expected_metrics)
                or not all(_safe_primitive(value) for value in metrics.values())
            ):
                return False
        return True
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return False


def _artifact_root(root_kind: str) -> Path:
    if root_kind == "repository":
        return _REPOSITORY_ROOT
    if root_kind == "runtime":
        return _RUNTIME_DATA_ROOT
    raise ValueError("unknown canvas artifact authority")


def _read_stable_artifact(
    root: Path,
    relative_name: str,
    maximum_bytes: int,
) -> bytes | None:
    """Read one regular, single-link file through its verified descriptor."""
    try:
        supplied_root = os.lstat(root)
        if stat.S_ISLNK(supplied_root.st_mode) or _has_reparse_attribute(
            supplied_root
        ):
            return None
        root = root.resolve(strict=True)
        root_metadata = os.lstat(root)
        if not stat.S_ISDIR(root_metadata.st_mode) or _has_reparse_attribute(
            root_metadata
        ):
            return None

        cursor = root
        component_identities: list[tuple[Path, tuple[int, int], bool]] = []
        parts = Path(relative_name).parts
        if not parts or Path(relative_name).is_absolute():
            return None
        for index, part in enumerate(parts):
            if part in {"", ".", ".."}:
                return None
            cursor /= part
            metadata = os.lstat(cursor)
            if stat.S_ISLNK(metadata.st_mode) or _has_reparse_attribute(metadata):
                return None
            is_directory = index < len(parts) - 1
            if is_directory and not stat.S_ISDIR(metadata.st_mode):
                return None
            component_identities.append(
                (cursor, _identity(metadata), is_directory)
            )

        before = os.lstat(cursor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or _has_reparse_attribute(before)
        ):
            return None
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(cursor, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or _has_reparse_attribute(opened)
                or _identity(opened) != _identity(before)
            ):
                return None
            opened_path = _descriptor_path(descriptor)
            if (
                opened_path is None
                or not _within_root(opened_path, root)
                or not _same_path(opened_path, cursor.resolve(strict=True))
            ):
                return None
            chunks: list[bytes] = []
            remaining = maximum_bytes + 1
            while remaining:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(descriptor)
            if _stable_metadata(after) != _stable_metadata(opened):
                return None
            final_path = _descriptor_path(descriptor)
            if final_path is None or not _same_path(final_path, opened_path):
                return None
            for component, expected_identity, is_directory in component_identities:
                current = os.lstat(component)
                if (
                    _identity(current) != expected_identity
                    or stat.S_ISLNK(current.st_mode)
                    or _has_reparse_attribute(current)
                    or (is_directory and not stat.S_ISDIR(current.st_mode))
                ):
                    return None
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    except (OSError, TypeError, ValueError):
        return None


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Threaded loopback server with a fixed concurrency and header budget."""

    daemon_threads = True
    request_queue_size = MAX_CONNECTIONS

    def __init__(self, server_address, handler_class) -> None:
        self._connection_slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(server_address, handler_class)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(HEADER_TIMEOUT_SECONDS)
        return request, address

    def process_request(self, request: socket.socket, client_address) -> None:
        if not self._connection_slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._connection_slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._connection_slots.release()


class CanvasRequestHandler(BaseHTTPRequestHandler):
    """Serve two exact artifacts without exposing a filesystem web root."""

    server_version = "AngeronaCanvas/2"
    sys_version = ""

    def _host_allowed(self) -> bool:
        supplied = self.headers.get_all("Host", failobj=[])
        port = int(self.server.server_port)  # type: ignore[attr-defined]
        return supplied == [f"{LOOPBACK_HOST}:{port}"]

    def _serve(self, *, include_body: bool) -> None:
        if not self._host_allowed():
            self.send_error(421, "Misdirected Request")
            return
        request_path = urlsplit(self.path).path
        selected = _ALLOWED_ARTIFACTS.get(request_path)
        if selected is None:
            self.send_error(404, "Not Found")
            return
        root_kind, relative_name, content_type, maximum_bytes = selected
        payload = _read_stable_artifact(
            _artifact_root(root_kind), relative_name, maximum_bytes
        )
        if payload is None:
            self.send_error(404, "Not Found")
            return
        if len(payload) > maximum_bytes:
            self.send_error(413, "Content Too Large")
            return
        if root_kind == "runtime" and not _valid_metrics(payload):
            self.send_error(422, "Invalid or stale metrics")
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self' 'unsafe-inline' "
            "https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.9/dist/vis-network.min.js; "
            "style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:",
        )
        self.end_headers()
        if include_body:
            self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        self._serve(include_body=True)

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib handler API
        self._serve(include_body=False)

    def log_message(self, _format: str, *_args: object) -> None:
        # Do not echo attacker-controlled request paths into a console or log.
        return


def create_server(port: int = DEFAULT_PORT) -> BoundedThreadingHTTPServer:
    """Create an IPv4 loopback server; port zero asks the OS for a safe port."""
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("canvas server port must be an integer between 0 and 65535")
    return BoundedThreadingHTTPServer((LOOPBACK_HOST, port), CanvasRequestHandler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--no-browser", action="store_true", help="do not open the canvas browser tab"
    )
    args = parser.parse_args(argv)
    try:
        server = create_server(args.port)
    except (OSError, ValueError) as exc:
        print(f"Canvas server could not start: {exc}", file=sys.stderr)
        return 2
    url = f"http://{LOOPBACK_HOST}:{server.server_port}/flow_canvas.html"
    print(f"Angerona canvas available at {url}")
    if not args.no_browser:
        try:
            webbrowser.open(url, new=2)
        except (OSError, webbrowser.Error):
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
