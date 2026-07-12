"""setup.py — Build the syscall_bridge CPython extension.

Usage (from AngeronaSuite/syscall_bridge/):
    python setup.py build_ext --inplace
    # Produces: syscall_bridge.cpython-310-win_amd64.pyd

Then copy the .pyd into AngeronaSuite/src/angerona/modules/ so the SYS module
can import it.

Requires:
    Windows x86-64
    Visual Studio Build Tools (MSVC) or cl.exe on PATH
    Python 3.10+ dev headers (normally included with CPython on Windows)

Compiler flags:
    /GS       — stack canary (buffer overrun protection)
    /DYNAMICBASE /NXCOMPAT — ASLR + DEP
    /O2       — optimise
    /W3       — warnings
"""
from setuptools import setup, Extension

module = Extension(
    "syscall_bridge",
    sources=["syscall_bridge.c"],
    extra_compile_args=[
        "/GS",           # stack canaries
        "/DYNAMICBASE",  # ASLR
        "/NXCOMPAT",     # DEP
        "/O2",           # optimise
        "/W3",           # warnings
    ],
    extra_link_args=[
        "/DYNAMICBASE",
        "/NXCOMPAT",
        "ntdll.lib",     # for type definitions (no actual imports needed)
    ],
    libraries=["kernel32", "ntdll"],
)

setup(
    name="syscall_bridge",
    version="1.0.0",
    description="Angerona indirect syscall bridge (Windows x64)",
    ext_modules=[module],
)
