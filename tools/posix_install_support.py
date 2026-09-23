"""Small stdlib-only helpers for the native, per-user source installer."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shlex
import shutil
import tempfile


def checked_text(value: str) -> str:
    if not value or any(ord(char) < 32 for char in value):
        raise ValueError("installation paths must not contain control characters")
    return value


def shell_launcher(python: str, root: str, data: str, *, setup: bool = False) -> str:
    values = [shlex.quote(checked_text(value)) for value in (python, root, data)]
    return (
        "#!/bin/sh\n"
        f"export ANGERONA_HOME={values[1]}\n"
        f"export ANGERONA_DATA={values[2]}\n"
        f"exec {values[0]} -m angerona{' --setup' if setup else ''} \"$@\"\n"
    )


def desktop_argument(value: str) -> str:
    # Desktop Entry string escaping is applied after Exec argument escaping.
    value = checked_text(value).replace("%", "%%")
    for char in ("\\", '"', "`", "$"):
        value = value.replace(char, "\\" + char)
    return '"' + value.replace("\\", "\\\\") + '"'


def systemd_argument(value: str, *, command: bool = False) -> str:
    value = checked_text(value).replace("%", "%%")
    if command:
        value = value.replace("$", "$$")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def atomic_write(path: Path, content: str, mode: int = 0o700) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".angerona-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def remove_staging(runtime: Path, staging: Path) -> None:
    """Delete only one installer-created generation, never a runtime root."""
    resolved_runtime = runtime.resolve(strict=True)
    if staging.is_symlink() or not staging.name.startswith("install."):
        raise ValueError("refusing unexpected installation staging path")
    resolved_staging = staging.resolve(strict=True)
    if resolved_staging.parent != resolved_runtime or not resolved_staging.is_dir():
        raise ValueError("staging directory escaped the runtime root")
    shutil.rmtree(resolved_staging)


def remove_wheelhouse(runtime: Path, staging: Path) -> None:
    resolved_runtime = runtime.resolve(strict=True)
    if staging.is_symlink() or staging.resolve(strict=True).parent != resolved_runtime:
        raise ValueError("staging directory escaped the runtime root")
    wheelhouse = staging / "wheelhouse"
    if wheelhouse.is_symlink() or wheelhouse.resolve(strict=True).parent != staging.resolve(strict=True):
        raise ValueError("wheelhouse escaped the installation generation")
    shutil.rmtree(wheelhouse)


def publish(root: Path, runtime: Path, staging: Path, data: Path, system: str) -> None:
    if staging.resolve(strict=True).parent != runtime.resolve(strict=True):
        raise ValueError("runtime generation is outside the installation root")
    python = staging / "venv/bin/python"
    if not python.is_file():
        raise ValueError("validated runtime interpreter is missing")
    launcher = Path.home() / ".local/bin/angerona"
    setup = launcher.with_name("angerona-setup")
    # Build and validate every payload before publishing the first entry point.
    launch_text = shell_launcher(str(python), str(root), str(data))
    setup_text = shell_launcher(str(python), str(root), str(data), setup=True)
    if system == "Darwin":
        native = Path.home() / "Applications/Angerona.command"
        native_text = launch_text
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share")
        native = base / "applications/angerona.desktop"
        native_text = (
            "[Desktop Entry]\nType=Application\nVersion=1.0\n"
            "Name=Angerona Security Suite\nComment=Local-first endpoint defense\n"
            f"Exec={desktop_argument(str(launcher))}\n"
            "Terminal=false\nCategories=System;Security;\nActions=Setup;\n\n"
            "[Desktop Action Setup]\nName=Full Setup\n"
            f"Exec={desktop_argument(str(setup))}\n"
        )
    atomic_write(setup, setup_text)
    atomic_write(launcher, launch_text)
    atomic_write(native, native_text, 0o700 if system == "Darwin" else 0o600)


def write_service(root: Path, staging: Path, data: Path, unit: Path) -> None:
    template = (root / "installer/linux/angerona-headless.service").read_text(encoding="utf-8")
    values = {
        "@PYTHON@": systemd_argument(str(staging / "venv/bin/python"), command=True),
        "@WORKDIR@": systemd_argument(str(root)),
        "@DATA_DIR@": systemd_argument(str(data)),
        "@ENV_DATA_DIR@": systemd_argument("ANGERONA_DATA=" + str(data)),
    }
    for token, value in values.items():
        template = template.replace(token, value)
    atomic_write(unit, template, 0o600)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("publish", "service", "cleanup", "clean-wheels"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--staging", type=Path, required=True)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--system", choices=("Darwin", "Linux"), required=True)
    parser.add_argument("--unit", type=Path)
    args = parser.parse_args()
    for value in (args.root, args.runtime, args.staging, args.data):
        checked_text(str(value))
        if not value.is_absolute():
            parser.error("installation paths must be absolute")
    if args.action == "cleanup":
        remove_staging(args.runtime, args.staging)
    elif args.action == "clean-wheels":
        remove_wheelhouse(args.runtime, args.staging)
    elif args.action == "publish":
        publish(args.root, args.runtime, args.staging, args.data, args.system)
    else:
        if args.unit is None:
            parser.error("service requires --unit")
        write_service(args.root, args.staging, args.data, args.unit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
