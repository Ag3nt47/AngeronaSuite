# pyoxidizer.bzl — PyOxidizer build config for Angerona HERMETIC binary.
#
# Requirements:
#   pyoxidizer >= 0.24   https://pyoxidizer.readthedocs.io/
#   Python 3.10 (match your dev environment)
#   Visual Studio Build Tools (MSVC) for Windows target
#
# Usage:
#   cd AngeronaSuite/hermetic
#   pyoxidizer build --release
#   # Output: hermetic/build/x86_64-pc-windows-msvc/release/install/angerona.exe
#
# After build, sign the binary:
#   signtool sign /fd sha256 /tr http://timestamp.digicert.com /td sha256 ^
#     /f your_cert.pfx /p <password> ..\dist\angerona.exe


def make_dist():
    return default_python_distribution(
        python_version = "3.10",
        build_target_triple = "x86_64-pc-windows-msvc",
    )


def make_exe(dist):
    policy = dist.make_python_packaging_policy()

    # Embed ALL Python source as in-memory bytecode — no loose .py on disk
    policy.set_resource_handling_mode("in-memory")
    policy.allow_in_memory_shared_library_loading = True
    policy.resources_location = "in-memory"
    policy.resources_location_fallback = "filesystem-relative:lib"

    # Include the full stdlib (needed for ctypes, mmap, sqlite3 etc.)
    policy.include_distribution_sources = False   # bytecode only
    policy.include_distribution_resources = True

    exe = dist.to_python_executable(
        name = "angerona",
        packaging_policy = policy,
        config = dist.make_python_interpreter_config(),
    )

    # ── entry point ──────────────────────────────────────────────────────────
    exe.run_module = "angerona"   # python -m angerona

    # ── add the AngeronaSuite package ────────────────────────────────────────
    for resource in exe.read_package_root(
        path = "..",                # AngeronaSuite/ root
        packages = ["angerona"],
    ):
        exe.add_python_resource(resource)

    # ── PySide6 (binary wheels — must be filesystem-relative) ────────────────
    # PySide6 uses .pyd + .dll side-by-side; embed sources in-memory but
    # allow .dlls to land on disk next to the binary.
    exe.add_python_resources(
        exe.pip_install(["PySide6==6.7.0"]),
    )

    # ── runtime dependencies ──────────────────────────────────────────────────
    exe.add_python_resources(
        exe.pip_install([
            "psutil",
            "pywin32",
            "requests",
            "yara-python",
            "python-dotenv",
        ])
    )

    return exe


def make_embedded_resources(exe):
    return exe.to_embedded_resources()


def make_install(exe):
    files = FileManifest()
    files.add_python_resource(".", exe)
    return files


# ── register targets ─────────────────────────────────────────────────────────
register_target("dist", make_dist)
register_target("exe", make_exe, depends = ["dist"], default = True)
register_target("resources", make_embedded_resources, depends = ["exe"])
register_target("install", make_install, depends = ["exe"], default_build_script = True)

resolve_targets()
