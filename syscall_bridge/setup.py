"""Held historical syscall bridge extension recipe.

This unsupported native implementation is retained for source review only.
Every setup command stops before importing packaging or compiler helpers.
Normal Angerona package builds and its explicitly degraded fallback are separate.
See README.md for unresolved correctness issues and replacement requirements.
"""

raise SystemExit(
    "ANGERONA_NATIVE_BRIDGE_BUILD_HELD: the historical syscall bridge is "
    "unsupported and must not be built or installed. See syscall_bridge/README.md."
)

# Historical recipe retained for review only; unreachable after the build hold.
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
