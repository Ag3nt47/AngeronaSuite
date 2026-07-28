"""Read-only static capability-drift auditing for Angerona extensions.

A signed capability manifest proves who approved a particular source digest,
but its permission list is still an assertion.  This module performs a bounded
AST inspection of one Python source file and compares observable sensitive
operations with the manifest's declared permissions.

The auditor deliberately never imports or executes the inspected file.  It also
does not authorize modules: static analysis is incomplete and its findings are
evidence for review or admission policy, not a sandbox or security boundary.
"""
from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


AUDIT_SCHEMA_VERSION = 1
DEFAULT_MAX_SOURCE_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_MANIFEST_BYTES = 128 * 1024

KNOWN_PERMISSIONS = frozenset({
    "ai.infer",
    "credentials.read",
    "event.emit",
    "filesystem.read",
    "filesystem.write",
    "firewall.modify",
    "network.connect",
    "process.control",
    "process.inspect",
    "registry.read",
    "registry.write",
    "telemetry.read",
})

HIGH_RISK_PERMISSIONS = frozenset({
    "credentials.read",
    "filesystem.write",
    "firewall.modify",
    "network.connect",
    "process.control",
    "registry.write",
})

_FILESYSTEM_READ_METHODS = frozenset({
    "exists", "glob", "is_dir", "is_file", "iterdir", "lstat", "read_bytes",
    "read_text", "resolve", "rglob", "stat",
})
_FILESYSTEM_WRITE_METHODS = frozenset({
    "chmod", "mkdir", "rename", "replace", "rmdir", "touch", "unlink",
    "write_bytes", "write_text",
})
_PROCESS_CONTROL_METHODS = frozenset({"kill", "resume", "suspend", "terminate"})

_EXACT_CALL_PERMISSIONS: dict[str, str] = {
    # Network clients and listeners.
    "socket.create_connection": "network.connect",
    "socket.socket": "network.connect",
    "urllib.request.urlopen": "network.connect",
    "http.client.HTTPConnection": "network.connect",
    "http.client.HTTPSConnection": "network.connect",
    "websockets.connect": "network.connect",
    "aiohttp.ClientSession": "network.connect",
    "httpx.Client": "network.connect",
    "httpx.AsyncClient": "network.connect",
    # Process creation or control.
    "os.kill": "process.control",
    "os.popen": "process.control",
    "os.system": "process.control",
    "subprocess.call": "process.control",
    "subprocess.check_call": "process.control",
    "subprocess.check_output": "process.control",
    "subprocess.Popen": "process.control",
    "subprocess.run": "process.control",
    "psutil.Popen": "process.control",
    # Process inspection.
    "psutil.Process": "process.inspect",
    "psutil.net_connections": "process.inspect",
    "psutil.pids": "process.inspect",
    "psutil.process_iter": "process.inspect",
    "wmi.WMI": "process.inspect",
    # Filesystem operations that are not methods on pathlib.Path.
    "os.makedirs": "filesystem.write",
    "os.mkdir": "filesystem.write",
    "os.remove": "filesystem.write",
    "os.rename": "filesystem.write",
    "os.replace": "filesystem.write",
    "os.rmdir": "filesystem.write",
    "os.unlink": "filesystem.write",
    "shutil.copy": "filesystem.write",
    "shutil.copy2": "filesystem.write",
    "shutil.copyfile": "filesystem.write",
    "shutil.copytree": "filesystem.write",
    "shutil.move": "filesystem.write",
    "shutil.rmtree": "filesystem.write",
    # Registry.
    "winreg.CreateKey": "registry.write",
    "winreg.CreateKeyEx": "registry.write",
    "winreg.DeleteKey": "registry.write",
    "winreg.DeleteKeyEx": "registry.write",
    "winreg.DeleteValue": "registry.write",
    "winreg.SetValue": "registry.write",
    "winreg.SetValueEx": "registry.write",
    "winreg.EnumKey": "registry.read",
    "winreg.EnumValue": "registry.read",
    "winreg.OpenKey": "registry.read",
    "winreg.OpenKeyEx": "registry.read",
    "winreg.QueryInfoKey": "registry.read",
    "winreg.QueryValue": "registry.read",
    "winreg.QueryValueEx": "registry.read",
    # Credential stores.
    "keyring.get_credential": "credentials.read",
    "keyring.get_password": "credentials.read",
    "win32cred.CredRead": "credentials.read",
    "win32crypt.CryptUnprotectData": "credentials.read",
}

_NETWORK_PREFIXES = (
    "requests.", "urllib3.", "httpx.", "aiohttp.", "websockets.",
)
_AI_PREFIXES = (
    "ollama.", "openai.", "anthropic.", "google.genai.", "google.generativeai.",
)
_FIREWALL_MARKERS = (
    "new-netfirewallrule",
    "remove-netfirewallrule",
    "set-netfirewallrule",
    "netsh advfirewall",
)
_DYNAMIC_CALLS: dict[str, tuple[str, str]] = {
    "__import__": (
        "dynamic.import",
        "Runtime import can bypass source-time dependency review.",
    ),
    "compile": (
        "dynamic.compile",
        "Runtime compilation can turn untrusted text into executable code.",
    ),
    "eval": (
        "dynamic.eval",
        "Dynamic evaluation executes data as Python expressions.",
    ),
    "exec": (
        "dynamic.exec",
        "Dynamic execution runs text as Python code.",
    ),
    "importlib.import_module": (
        "dynamic.import",
        "Runtime import can bypass source-time dependency review.",
    ),
    "importlib.util.module_from_spec": (
        "dynamic.import",
        "Dynamic module construction expands the executable trust boundary.",
    ),
    "importlib.util.spec_from_file_location": (
        "dynamic.import",
        "Loading code from a runtime path expands the executable trust boundary.",
    ),
    "marshal.load": (
        "dynamic.deserialization",
        "Deserializing executable bytecode is unsafe for untrusted input.",
    ),
    "marshal.loads": (
        "dynamic.deserialization",
        "Deserializing executable bytecode is unsafe for untrusted input.",
    ),
    "pickle.load": (
        "dynamic.deserialization",
        "Pickle deserialization can execute attacker-controlled code.",
    ),
    "pickle.loads": (
        "dynamic.deserialization",
        "Pickle deserialization can execute attacker-controlled code.",
    ),
}


@dataclass(frozen=True)
class CapabilitySignal:
    permission: str
    detector: str
    line: int
    confidence: str = "high"

    def as_dict(self) -> dict[str, Any]:
        return {
            "permission": self.permission,
            "detector": self.detector,
            "line": self.line,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class AuditFinding:
    severity: str
    code: str
    message: str
    line: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
            "line": self.line,
        }


class _CapabilityVisitor(ast.NodeVisitor):
    """Collect conservative evidence without evaluating source expressions."""

    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}
        self.signals: set[CapabilitySignal] = set()
        self.findings: set[AuditFinding] = set()

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for item in node.names:
            local = item.asname or item.name.split(".", 1)[0]
            self.aliases[local] = item.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        module = node.module or ""
        for item in node.names:
            if item.name == "*":
                continue
            local = item.asname or item.name
            self.aliases[local] = f"{module}.{item.name}".strip(".")
        self.generic_visit(node)

    def _qualified(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            parent = self._qualified(node.value)
            return f"{parent}.{node.attr}".strip(".")
        return ""

    def _signal(
        self,
        permission: str,
        detector: str,
        node: ast.AST,
        confidence: str = "high",
    ) -> None:
        self.signals.add(
            CapabilitySignal(
                permission=permission,
                detector=detector,
                line=max(0, int(getattr(node, "lineno", 0) or 0)),
                confidence=confidence,
            )
        )

    def _finding(
        self,
        severity: str,
        code: str,
        message: str,
        node: ast.AST,
    ) -> None:
        self.findings.add(
            AuditFinding(
                severity=severity,
                code=code,
                message=message,
                line=max(0, int(getattr(node, "lineno", 0) or 0)),
            )
        )

    @staticmethod
    def _constant_string(node: ast.AST | None) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    def _inspect_open(self, node: ast.Call) -> None:
        mode_node: ast.AST | None = None
        if len(node.args) >= 2:
            mode_node = node.args[1]
        for keyword in node.keywords:
            if keyword.arg == "mode":
                mode_node = keyword.value
        mode = self._constant_string(mode_node)
        if mode is None and mode_node is not None:
            self._signal(
                "filesystem.write",
                "open(dynamic-mode)",
                node,
                confidence="medium",
            )
            return
        normalized = mode or "r"
        if any(flag in normalized for flag in ("w", "a", "x", "+")):
            self._signal("filesystem.write", f"open(mode={normalized})", node)
        else:
            self._signal("filesystem.read", f"open(mode={normalized})", node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        qualified = self._qualified(node.func)
        short_name = node.func.id if isinstance(node.func, ast.Name) else ""
        attr_name = node.func.attr if isinstance(node.func, ast.Attribute) else ""

        if qualified in ("builtins.open", "open") or short_name == "open":
            self._inspect_open(node)

        permission = _EXACT_CALL_PERMISSIONS.get(qualified)
        if permission:
            self._signal(permission, qualified, node)
        elif qualified.startswith(_NETWORK_PREFIXES):
            self._signal("network.connect", qualified, node)
        elif qualified.startswith(_AI_PREFIXES):
            self._signal("ai.infer", qualified, node)
            self._signal(
                "network.connect",
                f"{qualified} transport",
                node,
                confidence="medium",
            )

        if attr_name in _FILESYSTEM_READ_METHODS:
            self._signal(
                "filesystem.read",
                f"path-method:{attr_name}",
                node,
                confidence="medium",
            )
        if attr_name in _FILESYSTEM_WRITE_METHODS:
            self._signal(
                "filesystem.write",
                f"path-method:{attr_name}",
                node,
                confidence="medium",
            )
        if attr_name in _PROCESS_CONTROL_METHODS:
            self._signal(
                "process.control",
                f"process-method:{attr_name}",
                node,
                confidence="medium",
            )

        dynamic = _DYNAMIC_CALLS.get(qualified) or _DYNAMIC_CALLS.get(short_name)
        if dynamic:
            self._finding("error", dynamic[0], dynamic[1], node)

        if qualified in (
            "ctypes.CDLL", "ctypes.PyDLL", "ctypes.WinDLL",
            "ctypes.cdll.LoadLibrary", "ctypes.windll.LoadLibrary",
        ):
            self._finding(
                "warning",
                "native.dynamic_library",
                "Dynamic native-library loading requires manual trust-boundary review.",
                node,
            )

        for keyword in node.keywords:
            if (
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
            ):
                self._finding(
                    "error",
                    "process.shell",
                    "shell=True expands command parsing and injection risk.",
                    node,
                )
                self._signal("process.control", "shell=True", node)

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:  # noqa: N802
        if isinstance(node.value, str):
            lowered = node.value.casefold()
            if any(marker in lowered for marker in _FIREWALL_MARKERS):
                self._signal(
                    "firewall.modify",
                    "firewall-command-literal",
                    node,
                    confidence="medium",
                )
        self.generic_visit(node)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalize_manifest(manifest: Mapping[str, Any] | Any) -> dict[str, Any]:
    if hasattr(manifest, "as_dict") and callable(manifest.as_dict):
        manifest = manifest.as_dict()
    if not isinstance(manifest, Mapping):
        raise ValueError("manifest must be a mapping or expose as_dict()")
    return dict(manifest)


def _base_report(source_name: str, digest: str) -> dict[str, Any]:
    return {
        "audit_schema_version": AUDIT_SCHEMA_VERSION,
        "source_name": source_name,
        "source_sha256": digest,
        "manifest": {
            "id": "",
            "version": "",
            "declared_permissions": [],
            "signature_present": False,
        },
        "status": "fail",
        "signals": [],
        "findings": [],
        "summary": {
            "declared_permissions": 0,
            "inferred_permissions": 0,
            "errors": 0,
            "warnings": 0,
        },
        "limitations": [
            "Static analysis cannot prove absence of runtime behavior.",
            "A passing audit is not authorization and does not replace isolation.",
            "Signature authenticity is verified by the capability-manifest gate.",
        ],
    }


def audit_source(
    source_path: Path,
    manifest: Mapping[str, Any] | Any,
    *,
    max_source_bytes: int = DEFAULT_MAX_SOURCE_BYTES,
) -> dict[str, Any]:
    """Audit one Python file without importing or executing it.

    The returned object is deterministic for the same source and manifest.  It
    intentionally includes only the source basename, not its full local path.
    """
    path = Path(source_path)
    source_name = path.name
    try:
        if path.is_symlink() or not path.is_file():
            raise ValueError("source must be a regular non-symlink file")
        size = path.stat().st_size
        limit = max(1, min(64 * 1024 * 1024, int(max_source_bytes)))
        if size <= 0 or size > limit:
            raise ValueError(f"source size must be between 1 and {limit} bytes")
        source_bytes = path.read_bytes()
    except Exception as exc:
        report = _base_report(source_name, "")
        finding = AuditFinding(
            "error",
            "source.unreadable",
            f"Cannot read bounded source ({type(exc).__name__}).",
        )
        report["findings"] = [finding.as_dict()]
        report["summary"]["errors"] = 1
        return report

    digest = _sha256(source_bytes)
    report = _base_report(source_name, digest)
    findings: set[AuditFinding] = set()

    try:
        normalized = _normalize_manifest(manifest)
    except Exception as exc:
        normalized = {}
        findings.add(
            AuditFinding("error", "manifest.invalid", f"Invalid manifest: {exc}")
        )

    raw_permissions = normalized.get("permissions", [])
    if not isinstance(raw_permissions, (list, tuple, set, frozenset)):
        findings.add(
            AuditFinding(
                "error",
                "manifest.permissions_invalid",
                "Manifest permissions must be a sequence of strings.",
            )
        )
        raw_permissions = []
    declared = {
        str(permission).strip()
        for permission in raw_permissions
        if isinstance(permission, str) and str(permission).strip()
    }
    unknown = sorted(declared - KNOWN_PERMISSIONS)
    for permission in unknown:
        findings.add(
            AuditFinding(
                "warning",
                "manifest.permission_unknown",
                f"Unknown declared permission: {permission}",
            )
        )

    report["manifest"] = {
        "id": str(normalized.get("id", ""))[:128],
        "version": str(normalized.get("version", ""))[:64],
        "declared_permissions": sorted(declared),
        "signature_present": bool(normalized.get("signature")),
    }

    expected_entrypoint = normalized.get("entrypoint")
    if expected_entrypoint and str(expected_entrypoint) != source_name:
        findings.add(
            AuditFinding(
                "error",
                "integrity.entrypoint_mismatch",
                "Manifest entrypoint does not match the adjacent source filename.",
            )
        )
    expected_digest = str(normalized.get("sha256", "") or "").casefold()
    if expected_digest and expected_digest != digest:
        findings.add(
            AuditFinding(
                "error",
                "integrity.sha256_mismatch",
                "Manifest digest does not match the inspected source.",
            )
        )

    try:
        source_text = source_bytes.decode("utf-8-sig")
        tree = ast.parse(source_text, filename=source_name)
    except (UnicodeError, SyntaxError) as exc:
        line = int(getattr(exc, "lineno", 0) or 0)
        findings.add(
            AuditFinding(
                "error",
                "source.parse_failed",
                f"Source cannot be safely parsed: {type(exc).__name__}",
                line,
            )
        )
        signals: list[CapabilitySignal] = []
    else:
        visitor = _CapabilityVisitor()
        visitor.visit(tree)
        signals = sorted(
            visitor.signals,
            key=lambda item: (
                item.permission, item.line, item.detector, item.confidence,
            ),
        )
        findings.update(visitor.findings)

    inferred = {signal.permission for signal in signals}
    first_signal: dict[str, CapabilitySignal] = {}
    for signal in signals:
        first_signal.setdefault(signal.permission, signal)

    for permission in sorted(inferred - declared):
        signal = first_signal[permission]
        severity = "error" if permission in HIGH_RISK_PERMISSIONS else "warning"
        findings.add(
            AuditFinding(
                severity,
                "permission.undeclared",
                (
                    f"Source shows {signal.confidence}-confidence use of "
                    f"{permission}, but the manifest does not declare it."
                ),
                signal.line,
            )
        )

    for permission in sorted((declared & HIGH_RISK_PERMISSIONS) - inferred):
        findings.add(
            AuditFinding(
                "info",
                "permission.unobserved",
                (
                    f"High-risk permission {permission} was declared but no static "
                    "signal was observed; manual review is still required."
                ),
            )
        )

    ordered_findings = sorted(
        findings,
        key=lambda item: (
            {"error": 0, "warning": 1, "info": 2}.get(item.severity, 3),
            item.code,
            item.line,
            item.message,
        ),
    )
    errors = sum(1 for finding in ordered_findings if finding.severity == "error")
    warnings = sum(
        1 for finding in ordered_findings if finding.severity == "warning"
    )
    report["signals"] = [signal.as_dict() for signal in signals]
    report["findings"] = [finding.as_dict() for finding in ordered_findings]
    report["status"] = "fail" if errors else "warn" if warnings else "pass"
    report["summary"] = {
        "declared_permissions": len(declared),
        "inferred_permissions": len(inferred),
        "errors": errors,
        "warnings": warnings,
    }
    return report


def audit_manifested_source(
    source_path: Path,
    manifest_path: Path,
    *,
    max_source_bytes: int = DEFAULT_MAX_SOURCE_BYTES,
    max_manifest_bytes: int = DEFAULT_MAX_MANIFEST_BYTES,
) -> dict[str, Any]:
    """Read a bounded JSON manifest and audit its adjacent Python source."""
    path = Path(manifest_path)
    try:
        if path.is_symlink() or not path.is_file():
            raise ValueError("manifest must be a regular non-symlink file")
        size = path.stat().st_size
        limit = max(1, min(4 * 1024 * 1024, int(max_manifest_bytes)))
        if size <= 0 or size > limit:
            raise ValueError(f"manifest size must be between 1 and {limit} bytes")
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise ValueError("manifest root must be a JSON object")
    except Exception as exc:
        report = _base_report(Path(source_path).name, "")
        finding = AuditFinding(
            "error",
            "manifest.unreadable",
            f"Cannot read bounded manifest ({type(exc).__name__}).",
        )
        report["findings"] = [finding.as_dict()]
        report["summary"]["errors"] = 1
        return report
    return audit_source(
        source_path,
        loaded,
        max_source_bytes=max_source_bytes,
    )
