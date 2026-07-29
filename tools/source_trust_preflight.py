"""Fail-closed structural trust checks for Angerona's elevated source launcher.

This does not claim that an editable checkout is equivalent to a signed release.
It prevents common path-redirection attacks while preserving source development.
"""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path


def _is_reparse(path: Path) -> bool:
    attrs = getattr(path.lstat(), "st_file_attributes", 0)
    return bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def validate_source_root(root: Path, interpreter: Path | None = None) -> tuple[bool, str]:
    try:
        root = Path(root).resolve(strict=True)
        if not root.is_dir() or _is_reparse(root):
            return False, "source root is not a real directory"
        required = (
            root / "start-angerona.bat",
            root / "pyproject.toml",
            root / "src" / "angerona" / "__init__.py",
        )
        for path in required:
            if not path.is_file() or _is_reparse(path):
                return False, f"required source file is missing or redirected: {path.name}"
            if root not in path.resolve(strict=True).parents:
                return False, f"required source file escapes the checkout: {path.name}"
        if interpreter is not None:
            executable = Path(interpreter).resolve(strict=True)
            expected = root / "venv"
            if _is_reparse(Path(interpreter)) or expected not in executable.parents:
                return False, "virtual-environment interpreter escapes the checkout"
        if os.name == "nt":
            import ctypes

            drive = Path(root.anchor)
            get_type = ctypes.WinDLL("kernel32", use_last_error=True).GetDriveTypeW
            get_type.argtypes = [ctypes.c_wchar_p]
            get_type.restype = ctypes.c_uint
            if get_type(str(drive)) != 3:
                return False, "elevated source checkout must reside on a fixed local volume"
        return True, "source trust preflight passed"
    except Exception as exc:
        return False, f"source trust preflight failed: {exc}"


def main() -> int:
    root = Path(os.environ.get("ANGERONA_INSTALL_ROOT", Path.cwd()))
    interpreter = Path(sys.executable)
    ok, detail = validate_source_root(root, interpreter)
    print(detail)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
