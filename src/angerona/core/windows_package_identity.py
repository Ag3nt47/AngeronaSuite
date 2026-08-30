"""Fail-closed Windows package identity proof for privileged startup.

``sys.frozen`` only describes how Python was packaged.  It is never authority
to request or retain an Administrator token.  The public MSIX publisher has not
yet provisioned an immutable production package-family pin, so the checked-in
defaults deliberately deny privileged frozen startup.  An independent signing
authority must inject the exact reviewed values before it signs a future MSIX.
"""
from __future__ import annotations

import ctypes
import sys
from dataclasses import dataclass
from typing import Callable, Final


# These are intentionally empty while the external, non-exportable Windows
# publisher described in docs/enterprise/RELEASE_SIGNING_BOUNDARY.md is absent.
# Do not source them from environment variables, argv, the registry, or an
# adjacent file: all of those are caller-controlled before UAC.
EXPECTED_PACKAGE_FAMILY_NAME: Final[str] = ""
EXPECTED_PACKAGE_PUBLISHER_ID: Final[str] = ""

_ERROR_INSUFFICIENT_BUFFER = 122
_MAX_IDENTITY_CHARS = 4096


@dataclass(frozen=True)
class NativePackageIdentity:
    """Identity returned by the current process's Windows package context."""

    full_name: str
    family_name: str


@dataclass(frozen=True)
class PackageAuthority:
    """Bounded result suitable for a startup refusal message and audit tests."""

    trusted: bool
    reason: str
    identity: NativePackageIdentity | None = None


IdentityQuery = Callable[[], NativePackageIdentity]


def _query_native_string(function_name: str) -> str:
    if sys.platform != "win32":
        raise OSError("Windows package identity APIs are unavailable")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    function = getattr(kernel32, function_name)
    function.argtypes = [ctypes.POINTER(ctypes.c_uint32), ctypes.c_wchar_p]
    function.restype = ctypes.c_long

    length = ctypes.c_uint32(0)
    status = int(function(ctypes.byref(length), None))
    if status != _ERROR_INSUFFICIENT_BUFFER:
        raise OSError(status, f"{function_name} size query failed")
    if not 2 <= int(length.value) <= _MAX_IDENTITY_CHARS:
        raise OSError(f"{function_name} returned an invalid bounded length")

    buffer = ctypes.create_unicode_buffer(int(length.value))
    status = int(function(ctypes.byref(length), buffer))
    if status != 0:
        raise OSError(status, f"{function_name} value query failed")
    value = buffer.value
    if (
        not value
        or len(value) >= _MAX_IDENTITY_CHARS
        or any(ord(character) < 32 for character in value)
    ):
        raise OSError(f"{function_name} returned an invalid identity")
    return value


def query_current_package_identity() -> NativePackageIdentity:
    """Read process-bound MSIX identity directly from bounded Win32 APIs."""

    return NativePackageIdentity(
        full_name=_query_native_string("GetCurrentPackageFullName"),
        family_name=_query_native_string("GetCurrentPackageFamilyName"),
    )


def verify_current_msix_authority(
    *,
    query: IdentityQuery = query_current_package_identity,
    expected_family_name: str = EXPECTED_PACKAGE_FAMILY_NAME,
    expected_publisher_id: str = EXPECTED_PACKAGE_PUBLISHER_ID,
) -> PackageAuthority:
    """Require the exact independently pinned package family and publisher.

    Dependency injection is limited to tests.  The application entry point uses
    only the immutable defaults above and never accepts caller-supplied pins.
    """

    family = str(expected_family_name)
    publisher_id = str(expected_publisher_id)
    if not family or not publisher_id:
        return PackageAuthority(
            False,
            "the independently governed MSIX package/publisher pin is not provisioned",
        )
    if (
        len(family) > 255
        or len(publisher_id) > 128
        or any(ord(character) < 33 for character in family + publisher_id)
        or not family.endswith(f"_{publisher_id}")
    ):
        return PackageAuthority(False, "the embedded MSIX authority pin is invalid")

    try:
        identity = query()
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        detail = str(exc).strip().replace("\r", " ").replace("\n", " ")[:240]
        suffix = f": {detail}" if detail else ""
        return PackageAuthority(False, f"Windows could not prove package identity{suffix}")

    full_name = str(identity.full_name)
    family_name = str(identity.family_name)
    package_name = family[: -(len(publisher_id) + 1)]
    if family_name != family:
        return PackageAuthority(False, "the current MSIX package family is not trusted", identity)
    if not full_name.startswith(f"{package_name}_") or not full_name.endswith(
        f"_{publisher_id}"
    ):
        return PackageAuthority(False, "the current MSIX full identity is not trusted", identity)
    if (
        len(full_name) >= _MAX_IDENTITY_CHARS
        or any(ord(character) < 32 for character in full_name + family_name)
    ):
        return PackageAuthority(False, "Windows returned malformed package identity", identity)
    return PackageAuthority(True, "exact Windows package family and publisher matched", identity)
