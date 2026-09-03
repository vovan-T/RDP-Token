"""Portable, read-only bootstrap for the official ESMART PKCS#11 modules.

The vendor dispatcher discovers token modules through HKLM.  To keep Token Admin
portable, this adapter redirects HKLM *inside the current process* to a temporary
volatile registry tree containing only the ESMART GOST D mapping.
"""

import ctypes
import os
import platform
import uuid
from contextlib import contextmanager
from pathlib import Path


CKR_OK = 0
CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x191
# Windows defines predefined HKEY values by sign-extending a 32-bit LONG.
HKEY_CURRENT_USER = ctypes.c_void_p(-2147483647)
HKEY_LOCAL_MACHINE = ctypes.c_void_p(-2147483646)
KEY_ALL_ACCESS = 0xF003F
REG_OPTION_VOLATILE = 1
REG_BINARY = 3
REG_SZ = 1

_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True) if platform.system() == "Windows" else None
if _advapi32 is not None:
    _advapi32.RegCreateKeyExW.argtypes = [
        ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_wchar_p,
        ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_ulong),
    ]
    _advapi32.RegCreateKeyExW.restype = ctypes.c_long
    _advapi32.RegSetValueExW.argtypes = [
        ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulong,
    ]
    _advapi32.RegSetValueExW.restype = ctypes.c_long
    _advapi32.RegOverridePredefKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    _advapi32.RegOverridePredefKey.restype = ctypes.c_long
    _advapi32.RegCloseKey.argtypes = [ctypes.c_void_p]
    _advapi32.RegCloseKey.restype = ctypes.c_long
    _advapi32.RegDeleteTreeW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    _advapi32.RegDeleteTreeW.restype = ctypes.c_long


class CK_VERSION(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("major", ctypes.c_ubyte), ("minor", ctypes.c_ubyte)]


class CK_FUNCTION_LIST_PREFIX(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("version", CK_VERSION),
        ("C_Initialize", ctypes.c_void_p),
        ("C_Finalize", ctypes.c_void_p),
        ("C_GetInfo", ctypes.c_void_p),
        ("C_GetFunctionList", ctypes.c_void_p),
        ("C_GetSlotList", ctypes.c_void_p),
    ]


def _check_win32(result: int, operation: str) -> None:
    if result:
        raise ctypes.WinError(result, operation)


def _create_key(root, path: str):
    handle = ctypes.c_void_p()
    disposition = ctypes.c_ulong()
    result = _advapi32.RegCreateKeyExW(
        root, path, 0, None, REG_OPTION_VOLATILE, KEY_ALL_ACCESS, None,
        ctypes.byref(handle), ctypes.byref(disposition),
    )
    _check_win32(result, f"RegCreateKeyExW({path})")
    return handle


def _set_value(handle, name: str, kind: int, value) -> None:
    if kind == REG_SZ:
        buffer = ctypes.create_unicode_buffer(value)
        pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
        size = ctypes.sizeof(buffer)
    else:
        buffer = (ctypes.c_ubyte * len(value)).from_buffer_copy(value)
        pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
        size = len(value)
    result = _advapi32.RegSetValueExW(handle, name, 0, kind, pointer, size)
    _check_win32(result, f"RegSetValueExW({name})")


@contextmanager
def _portable_hklm(module_dir: Path):
    base_name = rf"Software\RDP-Token\PortableHKLM-{uuid.uuid4()}"
    base = _create_key(HKEY_CURRENT_USER, base_name)
    token = _create_key(base, r"SOFTWARE\ISBC CORP\PKCS11\ESMARTTokenGOSTD")
    try:
        _set_value(token, "Atr", REG_BINARY, bytes.fromhex("3B7C95000045534D415254474F53543130"))
        _set_value(token, "Mask", REG_BINARY, b"\xff" * 17)
        _set_value(token, "Path", REG_SZ, str(module_dir / "esmart_token_gost_mod.dll"))
        _check_win32(
            _advapi32.RegOverridePredefKey(HKEY_LOCAL_MACHINE, base),
            "RegOverridePredefKey(HKLM)",
        )
        yield
    finally:
        _advapi32.RegOverridePredefKey(HKEY_LOCAL_MACHINE, None)
        _advapi32.RegCloseKey(token)
        _advapi32.RegCloseKey(base)
        _advapi32.RegDeleteTreeW(HKEY_CURRENT_USER, base_name)


def probe_esmart(module_dir: Path) -> dict:
    if platform.system() != "Windows":
        raise RuntimeError("Portable ESMART probe is currently implemented for Windows only")
    module_dir = module_dir.resolve()
    os.add_dll_directory(str(module_dir))
    with _portable_hklm(module_dir):
        library = ctypes.CDLL(str(module_dir / "isbc_pkcs11_main.dll"))
        get_functions = library.C_GetFunctionList
        get_functions.argtypes = [ctypes.POINTER(ctypes.POINTER(CK_FUNCTION_LIST_PREFIX))]
        get_functions.restype = ctypes.c_ulong
        functions = ctypes.POINTER(CK_FUNCTION_LIST_PREFIX)()
        result = int(get_functions(ctypes.byref(functions)))
        if result != CKR_OK or not functions:
            raise RuntimeError(f"C_GetFunctionList: 0x{result:08X}")

        table = functions.contents
        initialize = ctypes.CFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(table.C_Initialize)
        finalize = ctypes.CFUNCTYPE(ctypes.c_ulong, ctypes.c_void_p)(table.C_Finalize)
        get_slots = ctypes.CFUNCTYPE(
            ctypes.c_ulong,
            ctypes.c_ubyte,
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.POINTER(ctypes.c_ulong),
        )(table.C_GetSlotList)

        result = int(initialize(None))
        if result not in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED):
            raise RuntimeError(f"C_Initialize: 0x{result:08X}")
        initialized_here = result == CKR_OK
        try:
            count = ctypes.c_ulong(0)
            result = int(get_slots(1, None, ctypes.byref(count)))
            if result != CKR_OK:
                raise RuntimeError(f"C_GetSlotList(count): 0x{result:08X}")
            slots = []
            if count.value:
                values = (ctypes.c_ulong * count.value)()
                result = int(get_slots(1, values, ctypes.byref(count)))
                if result != CKR_OK:
                    raise RuntimeError(f"C_GetSlotList(values): 0x{result:08X}")
                slots = list(values[:count.value])
            return {
                "pkcs11_version": f"{table.version.major}.{table.version.minor}",
                "slots": slots,
            }
        finally:
            if initialized_here:
                finalize(None)
