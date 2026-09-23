from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile

import pytest

from tools import build_macos_intel_crypto as intel
from tools import check_native_gui as gui_probe
from tools import posix_install_support as support

ROOT = Path(__file__).resolve().parents[1]


def _available_posix_shell() -> str:
    if os.name == "nt":
        git = shutil.which("git")
        if git:
            for parent in tuple(Path(git).parents)[:3]:
                candidate = parent / "bin/bash.exe"
                if candidate.is_file():
                    return str(candidate)
        pytest.skip("Git Bash is required for the native shell regression on Windows")
    return "/bin/sh"


@pytest.mark.parametrize("architecture", ["arm64", "x86_64"])
@pytest.mark.parametrize("custom_data", [False, True])
def test_macos_installer_keeps_application_support_paths_in_one_argument(tmp_path: Path, architecture: str, custom_data: bool) -> None:
    """Execute real installer setup; stop before its first directory mutation."""
    fake = tmp_path / "fake-bin"
    fake.mkdir()
    scripts = {
        "uname": 'case "$1" in -s) printf "Darwin\\n" ;; -m) printf "%s\\n" "$TEST_ARCH" ;; *) exit 2 ;; esac',
        "id": 'printf "1000\\n"',
        "sw_vers": 'printf "15.0\\n"',
        "python3.12": "exit 0",
        "mkdir": 'printf "%s\\0" "$@" > "$TEST_CAPTURE"\nexit 72',
    }
    for name, script in scripts.items():
        entry = fake / name
        entry.write_text("#!/bin/sh\n" + script + "\n", encoding="utf-8", newline="\n")
        entry.chmod(0o700)
    driver = r'''
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) fixture=$(cygpath -u "$1"); installer=$(cygpath -u "$2") ;;
    *) fixture=$1; installer=$2 ;;
esac
export PATH="$fixture/fake-bin:$PATH"
export HOME="$fixture/User space"
export PYTHON="$fixture/fake-bin/python3.12"
export TEST_CAPTURE="$fixture/captured-arguments"
unset ANGERONA_DATA
if [ "$TEST_CUSTOM_DATA" = 1 ]; then
    export ANGERONA_DATA="$fixture/Custom data folder"
fi
exec /bin/sh "$installer" --no-autostart --build-intel-crypto
'''
    env = dict(os.environ, TEST_ARCH=architecture, TEST_CUSTOM_DATA="1" if custom_data else "0")
    result = subprocess.run([_available_posix_shell(), "-c", driver, "fixture", str(tmp_path), str(ROOT / "install-angerona.sh")], env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 72, result.stderr
    arguments = (tmp_path / "captured-arguments").read_bytes().decode().split("\0")[:-1]
    assert len(arguments) == 4 and arguments[0] == "-p"
    assert arguments[1].endswith("/User space/Library/Application Support/Angerona/runtime")
    expected_data = "/Custom data folder" if custom_data else "/User space/Library/Application Support/Angerona"
    assert arguments[2].endswith(expected_data)
    assert arguments[3].endswith("/User space/.local/bin")
    assert not (tmp_path / "User space").exists()  # All filesystem writes were intercepted.


@pytest.mark.parametrize("purge", [False, True])
def test_macos_uninstaller_passes_whole_paths_to_inert_removal(tmp_path: Path, purge: bool) -> None:
    fake = tmp_path / "fake-bin"
    fake.mkdir()
    for name, script in {
        "uname": 'printf "Darwin\\n"',
        "rm": 'printf "%s\\0" "$@" >> "$TEST_CAPTURE"',
    }.items():
        entry = fake / name
        entry.write_text("#!/bin/sh\n" + script + "\n", encoding="utf-8", newline="\n")
        entry.chmod(0o700)
    driver = r'''
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) fixture=$(cygpath -u "$1"); uninstaller=$(cygpath -u "$2") ;;
    *) fixture=$1; uninstaller=$2 ;;
esac
export PATH="$fixture/fake-bin:$PATH"
export HOME="$fixture/User space"
export TEST_CAPTURE="$fixture/captured-arguments"
unset ANGERONA_DATA
if [ "$TEST_PURGE" = 1 ]; then
    exec /bin/sh "$uninstaller" --purge-data
fi
exec /bin/sh "$uninstaller"
'''
    env = dict(os.environ, TEST_PURGE="1" if purge else "0")
    result = subprocess.run([_available_posix_shell(), "-c", driver, "fixture", str(tmp_path), str(ROOT / "uninstall-angerona.sh")], env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    arguments = (tmp_path / "captured-arguments").read_bytes().decode().split("\0")[:-1]
    assert any(value.endswith("/User space/Library/Application Support/Angerona/runtime") for value in arguments)
    data_targets = [value for value in arguments if value.endswith("/User space/Library/Application Support/Angerona")]
    assert len(data_targets) == int(purge)


def test_launcher_round_trips_shell_metacharacters_without_evaluation() -> None:
    value = "/Users/A 'quoted' $USER `touch marker` %name\\folder"
    payload = support.shell_launcher(value + "/python", value, value + "/data", setup=True)
    commands = [shlex.split(line) for line in payload.splitlines()[1:]]
    assert commands == [
        ["export", "ANGERONA_HOME=" + value],
        ["export", "ANGERONA_DATA=" + value + "/data"],
        ["exec", value + "/python", "-m", "angerona", "--setup", "$@"],
    ]
    assert '`touch marker`' in payload  # retained literal path text, inside shell quotes


@pytest.mark.parametrize("value", ["/tmp/a\nb", "/tmp/a\rb", "/tmp/a\x00b", ""])
def test_launcher_rejects_control_characters(value: str) -> None:
    with pytest.raises(ValueError):
        support.shell_launcher("/python", value, "/data")


def test_systemd_path_does_not_expand_specifiers_or_environment() -> None:
    value = '/tmp/quoted "a"/$HOME/%h'
    assert support.systemd_argument(value, command=True) == '"/tmp/quoted \\"a\\"/$$HOME/%%h"'
    assert support.systemd_argument(value) == '"/tmp/quoted \\"a\\"/$HOME/%%h"'
    assert "%%h" in support.desktop_argument(value)
    assert "\\\\$HOME" in support.desktop_argument(value)


def test_cleanup_cannot_remove_runtime_or_sibling(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    previous = runtime / "venv"
    previous.mkdir()
    (previous / "keep").write_text("old runtime")
    sibling = tmp_path / "install.outside"
    sibling.mkdir()
    for target in (runtime, previous, sibling):
        with pytest.raises(ValueError):
            support.remove_staging(runtime, target)
    stage = runtime / "install.fixture"
    stage.mkdir()
    (stage / "incomplete").write_text("new")
    support.remove_staging(runtime, stage)
    assert not stage.exists()
    assert (previous / "keep").read_text() == "old runtime"


def test_publish_validates_all_paths_before_replacing_working_launcher(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    runtime = tmp_path / "runtime"
    stage = runtime / "install.fixture"
    (stage / "venv/bin").mkdir(parents=True)
    (stage / "venv/bin/python").write_text("interpreter")
    launcher = tmp_path / ".local/bin/angerona"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("old working launcher")
    with pytest.raises(ValueError):
        support.publish(tmp_path, runtime, stage, Path("/bad\npath"), "Linux")
    assert launcher.read_text() == "old working launcher"
    support.publish(tmp_path, runtime, stage, tmp_path / "data", "Darwin")
    assert str(stage).replace("\\", "") in launcher.read_text().replace("\\", "")
    assert (tmp_path / "Applications/Angerona.command").is_file()


def test_exact_intel_base_lock_omits_only_separately_built_crypto() -> None:
    base = ROOT / "release/locks/posix/source"
    arm = json.loads((base / "macos-arm64.manifest.json").read_text())
    intel_base = json.loads((base / "macos-x86_64-base.manifest.json").read_text())
    names = lambda document: {entry["name"].casefold(): entry["version"] for entry in document["artifacts"]}
    expected = names(arm)
    assert expected.pop("cryptography") == "50.0.0"
    assert names(intel_base) == expected
    assert intel_base["target"] == "macos-x86_64-base"
    hashes = {line.strip().split(":", 1)[1] for line in (base / "macos-x86_64-base.txt").read_text().splitlines() if "--hash=sha256:" in line}
    assert hashes == {entry["sha256"] for entry in intel_base["artifacts"]}


def _archive(path: Path, members: list[tuple[str, bytes, bytes]]) -> None:
    with tarfile.open(path, "w:gz") as stream:
        for name, payload, kind in members:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.size = len(payload)
            if kind == tarfile.SYMTYPE:
                info.linkname = "../../outside"
            stream.addfile(info, io.BytesIO(payload))


@pytest.mark.parametrize("name,kind", [("../outside", tarfile.REGTYPE), ("/outside", tarfile.REGTYPE), ("cryptography-50.0.0/link", tarfile.SYMTYPE)])
def test_source_extraction_rejects_escapes_and_links(tmp_path: Path, name: str, kind: bytes) -> None:
    path = tmp_path / "source.tar.gz"
    _archive(path, [(name, b"bad", kind)])
    with pytest.raises(ValueError, match="unsafe member"):
        intel.unpack_source(path, tmp_path / "source")
    assert not (tmp_path / "outside").exists()


def test_pinned_fetch_rejects_changed_bytes_before_they_execute(tmp_path: Path, monkeypatch) -> None:
    class Response(io.BytesIO):
        url = "https://files.pythonhosted.org/reviewed"
    monkeypatch.setattr(intel.urllib.request, "urlopen", lambda *a, **k: Response(b"changed"))
    item = {"filename": "source.tar.gz", "url": "https://files.pythonhosted.org/reviewed", "size": 7, "sha256": hashlib.sha256(b"trusted").hexdigest()}
    with pytest.raises(ValueError, match="SHA-256"):
        intel.fetch_pinned(item, tmp_path)


def test_build_environment_ignores_injected_compiler_and_index_settings(tmp_path: Path, monkeypatch) -> None:
    for key in ("RUSTC_WRAPPER", "RUSTFLAGS", "CARGO_HOME", "PIP_INDEX_URL", "PYTHONPATH", "OPENSSL_DIR"):
        monkeypatch.setenv(key, "attacker-controlled")
    env = intel.build_environment(tmp_path, tmp_path / "openssl")
    assert "RUSTC_WRAPPER" not in env and "RUSTFLAGS" not in env
    assert "PIP_INDEX_URL" not in env and "PYTHONPATH" not in env
    assert env["CARGO_HOME"] == str(tmp_path / "cargo")
    assert env["CARGO_BUILD_JOBS"] == "2"
    assert env["OPENSSL_STATIC"] == "1"


def test_linux_gui_probe_reports_the_missing_native_library(monkeypatch) -> None:
    def load(name: str):
        if name == "libxcb-cursor.so.0":
            raise OSError("not installed")
        return object()
    monkeypatch.setattr(gui_probe.ctypes, "CDLL", load)
    assert gui_probe.missing_linux_libraries() == ["libxcb-cursor.so.0"]


@pytest.mark.parametrize("manager,expected", [("apt-get", "libxcb-cursor0"), ("dnf", "xcb-util-cursor")])
def test_linux_prerequisite_install_uses_fixed_package_arguments(monkeypatch, manager: str, expected: str) -> None:
    monkeypatch.setattr(gui_probe.shutil, "which", lambda name: "/usr/bin/" + name if name == manager else None)
    commands = gui_probe.package_commands(noninteractive=True)
    assert commands[-1][:3] == ["sudo", manager, "install"]
    assert expected in commands[-1]
    assert "-y" in commands[-1]
    assert not any(";" in item or "$" in item for item in commands[-1])


def test_linux_prerequisite_check_does_not_install_without_explicit_request(monkeypatch, capsys) -> None:
    monkeypatch.setattr(gui_probe.sys, "platform", "linux")
    monkeypatch.setattr(gui_probe, "missing_linux_libraries", lambda: ["libxcb-cursor.so.0"])
    monkeypatch.setattr(gui_probe, "package_commands", lambda **kwargs: [["sudo", "apt-get", "install", "libxcb-cursor0"]])
    monkeypatch.setattr(gui_probe.subprocess, "run", lambda *args, **kwargs: pytest.fail("readiness check tried to install packages"))
    assert gui_probe.check_system_libraries() == 3
    assert "sudo apt-get install libxcb-cursor0" in capsys.readouterr().err


def test_gui_probe_runs_bounded_isolated_offscreen_child(monkeypatch) -> None:
    monkeypatch.setenv("QT_PLUGIN_PATH", "injected-plugin-path")
    monkeypatch.setenv("PYTHONPATH", "injected-python-path")
    seen = {}
    def run(command, **kwargs):
        seen.update(command=command, **kwargs)
        return subprocess.CompletedProcess(command, 0, '{"rendered":true}', "")
    monkeypatch.setattr(gui_probe.subprocess, "run", run)
    assert gui_probe.check_gui() == 0
    assert "-I" in seen["command"] and seen["command"][-1] == "--qt-child"
    assert seen["timeout"] == 40
    assert seen["env"]["QT_QPA_PLATFORM"] == "offscreen"
    assert "QT_PLUGIN_PATH" not in seen["env"] and "PYTHONPATH" not in seen["env"]


def test_gui_render_probe_accepts_retina_pixel_dimensions() -> None:
    from types import SimpleNamespace
    image = SimpleNamespace(isNull=lambda: False, devicePixelRatio=lambda: 2.0, width=lambda: 600, height=lambda: 140)
    assert gui_probe.rendered_size_matches(image, 300, 70)
    assert not gui_probe.rendered_size_matches(image, 600, 140)


def test_aborted_gui_child_is_an_install_failure(monkeypatch, capsys) -> None:
    monkeypatch.setattr(gui_probe.subprocess, "run", lambda command, **kwargs: subprocess.CompletedProcess(command, -6, "", "Qt plugin initialization failed"))
    monkeypatch.setattr(gui_probe, "check_system_libraries", lambda: 3)
    assert gui_probe.check_gui() == 3
    assert "previous runtime is unchanged" in capsys.readouterr().err


def test_native_ci_and_installer_gate_launchers_on_real_gui_probe() -> None:
    installer = (ROOT / "install-angerona.sh").read_text()
    assert installer.index('"$VENV/bin/python" "$ROOT/tools/check_native_gui.py"') < installer.index('posix_install_support.py" publish')
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    assert "Install runtime and render an offscreen QApplication" in workflow
    assert "check_native_gui.py --install-system-libraries --yes" in workflow


@pytest.mark.skipif(os.name == "nt", reason="native shell fixture runs in Linux/macOS CI")
def test_failed_download_preserves_existing_runtime_and_launcher(tmp_path: Path) -> None:
    """Execute the installer through a deliberate download failure, without networking."""
    fake = tmp_path / "fake-bin"
    fake.mkdir()
    scripts = {
        "uname": 'case "$1" in -s) printf "Linux\\n" ;; -m) printf "x86_64\\n" ;; *) exit 2 ;; esac',
        "id": "printf '1000\\n'",
        "python3.12": "case \"$*\" in *'pip download'*) exit 71 ;; *'posix_install_support.py'*) exec \"$REAL_PYTHON\" \"$@\" ;; esac\nexit 0",
    }
    for name, script in scripts.items():
        entry = fake / name
        entry.write_text("#!/bin/sh\n" + script + "\n")
        entry.chmod(0o700)
    runtime = tmp_path / ".local/share/angerona"
    old = runtime / "venv"
    old.mkdir(parents=True)
    (old / "keep").write_text("previous runtime")
    launcher = tmp_path / ".local/bin/angerona"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("working")
    env = dict(os.environ, HOME=str(tmp_path), PATH=str(fake) + os.pathsep + os.environ["PATH"], PYTHON=str(fake / "python3.12"), REAL_PYTHON=shutil.which("python3") or "python3")
    for key in ("XDG_DATA_HOME", "XDG_STATE_HOME", "ANGERONA_DATA"):
        env.pop(key, None)
    result = subprocess.run(["/bin/sh", str(ROOT / "install-angerona.sh"), "--no-autostart"], env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 71, result.stderr
    assert (old / "keep").read_text() == "previous runtime"
    assert launcher.read_text() == "working"
    assert not list(runtime.glob("install.*"))
    assert not (runtime / ".install-lock").exists()
