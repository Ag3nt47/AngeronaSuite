"""Check Qt's native libraries and render an inert widget before desktop install."""
from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys


# Runtime libraries from Qt's Linux/XCB requirements; no compiler packages.
LINUX_LIBRARIES = (
    "libGL.so.1", "libEGL.so.1", "libOpenGL.so.0", "libfontconfig.so.1",
    "libfreetype.so.6", "libdbus-1.so.3", "libglib-2.0.so.0", "libX11.so.6",
    "libX11-xcb.so.1", "libxcb.so.1", "libxcb-cursor.so.0", "libxcb-icccm.so.4",
    "libxcb-image.so.0", "libxcb-keysyms.so.1", "libxcb-randr.so.0",
    "libxcb-render-util.so.0", "libxcb-render.so.0", "libxcb-shape.so.0",
    "libxcb-shm.so.0", "libxcb-sync.so.1", "libxcb-xfixes.so.0",
    "libxcb-xkb.so.1", "libxkbcommon.so.0", "libxkbcommon-x11.so.0",
)
APT_PACKAGES = (
    "libgl1", "libegl1", "libopengl0", "libfontconfig1", "libfreetype6",
    "libdbus-1-3", "libglib2.0-0t64", "libx11-6", "libx11-xcb1", "libxcb1",
    "libxcb-cursor0", "libxcb-icccm4", "libxcb-image0", "libxcb-keysyms1",
    "libxcb-randr0", "libxcb-render-util0", "libxcb-render0", "libxcb-shape0",
    "libxcb-shm0", "libxcb-sync1", "libxcb-xfixes0", "libxcb-xkb1",
    "libxkbcommon0", "libxkbcommon-x11-0",
)
DNF_PACKAGES = (
    "libglvnd-glx", "libglvnd-egl", "libglvnd-opengl", "fontconfig", "freetype",
    "dbus-libs", "glib2", "libX11", "libxcb", "xcb-util-cursor", "xcb-util-wm",
    "xcb-util-image", "xcb-util-keysyms", "xcb-util-renderutil",
    "libxkbcommon", "libxkbcommon-x11",
)


def missing_linux_libraries() -> list[str]:
    missing: list[str] = []
    for library in LINUX_LIBRARIES:
        try:
            ctypes.CDLL(library)
        except OSError:
            missing.append(library)
    return missing


def package_commands(*, noninteractive: bool = False) -> list[list[str]]:
    # Package names are fixed literals, never parsed from exception/model text.
    flags = ["-y"] if noninteractive else []
    if shutil.which("apt-get"):
        # Ubuntu24.04 is the reviewed apt target. Older distributions may need
        # the pre-time_t-transition libglib2.0-0 package instead; docs cover it.
        return [["sudo", "apt-get", "update"], ["sudo", "apt-get", "install", *flags, *APT_PACKAGES]]
    if shutil.which("dnf"):
        return [["sudo", "dnf", "install", *flags, *DNF_PACKAGES]]
    return []


def check_system_libraries(*, install: bool = False, noninteractive: bool = False) -> int:
    if not sys.platform.startswith("linux"):
        return 0
    missing = missing_linux_libraries()
    if not missing:
        print("Qt/XCB system libraries are available.")
        return 0
    print("Missing Qt/XCB runtime libraries: " + ", ".join(missing), file=sys.stderr)
    commands = package_commands(noninteractive=noninteractive)
    if not install:
        for command in commands:
            print("Install with: " + shlex.join(command), file=sys.stderr)
        print("See docs/NATIVE_INSTALL.md for supported distributions.", file=sys.stderr)
        return 3
    if not commands:
        print("Install the listed libraries with your distribution package manager, then rerun setup.", file=sys.stderr)
        return 3
    for command in commands:
        subprocess.run(command, check=True, timeout=900)
    return check_system_libraries()


def qt_child() -> int:
    # A broken Qt plugin can abort the process. Keep this probe in a bounded
    # child and prevent a large core file from being written on install failure.
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except ImportError:
        pass
    import PySide6
    from PySide6.QtWidgets import QApplication, QLabel

    if sys.platform.startswith("linux"):
        plugin = Path(PySide6.__file__).parent / "Qt/plugins/platforms/libqxcb.so"
        ctypes.CDLL(str(plugin))  # Validate real plugin dependencies without an X server.
    app = QApplication([])
    label = QLabel("Angerona native GUI check")
    label.resize(300, 70)
    label.show()
    app.processEvents()
    rendered = label.grab()
    if not rendered_size_matches(rendered, label.width(), label.height()):
        raise RuntimeError("Qt did not render the test widget")
    label.close()
    app.processEvents()
    print(json.dumps({"platform": app.platformName(), "rendered": True, "xcb_loadable": sys.platform.startswith("linux")}))
    return 0


def rendered_size_matches(pixmap, width: int, height: int) -> bool:
    # Retina/high-DPI pixmaps contain physical pixels; widgets use logical pixels.
    ratio = pixmap.devicePixelRatio()
    return (
        not pixmap.isNull() and ratio > 0
        and abs(pixmap.width() / ratio - width) <= 1
        and abs(pixmap.height() / ratio - height) <= 1
    )


def check_gui() -> int:
    env = dict(os.environ)
    for name in ("QT_PLUGIN_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH", "QML2_IMPORT_PATH", "PYTHONPATH"):
        env.pop(name, None)
    env["QT_QPA_PLATFORM"] = "offscreen"
    try:
        result = subprocess.run(
            [sys.executable, "-I", str(Path(__file__).resolve()), "--qt-child"],
            env=env, capture_output=True, text=True, timeout=40,
        )
    except subprocess.TimeoutExpired:
        print("Qt startup timed out. Install the native GUI prerequisites described in docs/NATIVE_INSTALL.md.", file=sys.stderr)
        return 3
    if result.returncode:
        print("Qt could not initialize or load its native libraries. Your previous runtime is unchanged.", file=sys.stderr)
        print(result.stderr[-4000:], file=sys.stderr)
        if sys.platform.startswith("linux"):
            check_system_libraries()
        return 3
    print("Native GUI probe passed: " + result.stdout.strip())
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--system-libraries", action="store_true")
    group.add_argument("--install-system-libraries", action="store_true")
    group.add_argument("--qt-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--yes", action="store_true", help="accept package-manager prompts after explicitly requesting installation")
    args = parser.parse_args()
    if args.qt_child:
        return qt_child()
    if args.system_libraries or args.install_system_libraries:
        return check_system_libraries(install=args.install_system_libraries, noninteractive=args.yes)
    return check_gui()


if __name__ == "__main__":
    raise SystemExit(main())
