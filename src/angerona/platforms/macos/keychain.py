"""Minimal macOS Keychain generic-password adapter.

This uses Apple's Security.framework directly so secret values never appear in
command-line arguments, temporary files, or environment variables during the
Keychain write.  The legacy Keychain C calls are used as a narrow compatibility
bridge until Angerona's native macOS host owns all secret operations.
"""
from __future__ import annotations

import ctypes
from ctypes import POINTER, byref, c_char_p, c_uint32, c_void_p

ERR_SEC_ITEM_NOT_FOUND = -25300


class KeychainError(RuntimeError):
    pass


def _frameworks():
    security = ctypes.CDLL(
        "/System/Library/Frameworks/Security.framework/Security"
    )
    core_foundation = ctypes.CDLL(
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
    )

    security.SecKeychainFindGenericPassword.argtypes = [
        c_void_p, c_uint32, c_char_p, c_uint32, c_char_p,
        POINTER(c_uint32), POINTER(c_void_p), POINTER(c_void_p),
    ]
    security.SecKeychainFindGenericPassword.restype = ctypes.c_int32
    security.SecKeychainAddGenericPassword.argtypes = [
        c_void_p, c_uint32, c_char_p, c_uint32, c_char_p,
        c_uint32, c_void_p, POINTER(c_void_p),
    ]
    security.SecKeychainAddGenericPassword.restype = ctypes.c_int32
    security.SecKeychainItemModifyAttributesAndData.argtypes = [
        c_void_p, c_void_p, c_uint32, c_void_p,
    ]
    security.SecKeychainItemModifyAttributesAndData.restype = ctypes.c_int32
    security.SecKeychainItemFreeContent.argtypes = [c_void_p, c_void_p]
    security.SecKeychainItemFreeContent.restype = ctypes.c_int32
    core_foundation.CFRelease.argtypes = [c_void_p]
    core_foundation.CFRelease.restype = None
    return security, core_foundation


def _encoded(value: str, field: str) -> bytes:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise KeychainError(f"{field} must be a non-empty string without NUL")
    return value.encode("utf-8")


def read_blob(service: str, account: str) -> bytes | None:
    security, core_foundation = _frameworks()
    service_b = _encoded(service, "service")
    account_b = _encoded(account, "account")
    length = c_uint32(0)
    data = c_void_p()
    item = c_void_p()
    status = security.SecKeychainFindGenericPassword(
        None,
        len(service_b), service_b,
        len(account_b), account_b,
        byref(length), byref(data), byref(item),
    )
    if status == ERR_SEC_ITEM_NOT_FOUND:
        return None
    if status != 0:
        raise KeychainError(f"Keychain read failed with OSStatus {status}")
    try:
        return ctypes.string_at(data, length.value)
    finally:
        security.SecKeychainItemFreeContent(None, data)
        if item:
            core_foundation.CFRelease(item)


def write_blob(service: str, account: str, payload: bytes) -> None:
    if not isinstance(payload, bytes):
        raise KeychainError("payload must be bytes")
    security, core_foundation = _frameworks()
    service_b = _encoded(service, "service")
    account_b = _encoded(account, "account")
    buffer = ctypes.create_string_buffer(payload)
    item = c_void_p()

    # Find the item without requesting its secret contents.  Existing items are
    # updated in place so their access-control policy remains attached.
    status = security.SecKeychainFindGenericPassword(
        None,
        len(service_b), service_b,
        len(account_b), account_b,
        None, None, byref(item),
    )
    try:
        if status == 0:
            changed = security.SecKeychainItemModifyAttributesAndData(
                item, None, len(payload), ctypes.cast(buffer, c_void_p)
            )
            if changed != 0:
                raise KeychainError(
                    f"Keychain update failed with OSStatus {changed}"
                )
            return
        if status != ERR_SEC_ITEM_NOT_FOUND:
            raise KeychainError(f"Keychain lookup failed with OSStatus {status}")
        added_item = c_void_p()
        added = security.SecKeychainAddGenericPassword(
            None,
            len(service_b), service_b,
            len(account_b), account_b,
            len(payload), ctypes.cast(buffer, c_void_p),
            byref(added_item),
        )
        if added != 0:
            raise KeychainError(f"Keychain write failed with OSStatus {added}")
        if added_item:
            core_foundation.CFRelease(added_item)
    finally:
        if item:
            core_foundation.CFRelease(item)
