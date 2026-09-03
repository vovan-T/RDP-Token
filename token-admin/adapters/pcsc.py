import ctypes
import platform
from ctypes import byref, c_char_p, c_long, c_uint32, c_void_p, create_string_buffer

from core.models import TokenInfo


SCARD_SCOPE_SYSTEM = 2
SCARD_SHARE_SHARED = 2
SCARD_PROTOCOL_T0 = 1
SCARD_PROTOCOL_T1 = 2
SCARD_LEAVE_CARD = 0
SCARD_S_SUCCESS = 0
SCARD_E_NO_SMARTCARD = 0x8010000C
SCARD_W_REMOVED_CARD = 0x80100069


def _library():
    if platform.system() == "Windows":
        return ctypes.WinDLL("winscard.dll")
    for name in ("libpcsclite.so.1", "libpcsclite.so"):
        try:
            return ctypes.CDLL(name)
        except OSError:
            continue
    raise RuntimeError("PC/SC library is not installed")


def _classify(atr: bytes):
    text = "".join(chr(value) if 32 <= value <= 126 else "." for value in atr)
    upper = text.upper()
    if "ESMARTGOST" in upper:
        return "ISBC", "ESMART Token GOST"
    if "RUTOKEN" in upper or "RUTOKN" in upper or "RTMC" in upper or "RTSC" in upper:
        return "Aktiv", "Rutoken"
    return "Не определён", text.strip(".") or "Смарт-карта"


def _check(result, operation):
    unsigned = ctypes.c_uint32(result).value
    if unsigned != SCARD_S_SUCCESS:
        raise RuntimeError(f"{operation}: PC/SC 0x{unsigned:08X}")


def scan_tokens():
    lib = _library()
    context = c_void_p()
    _check(lib.SCardEstablishContext(SCARD_SCOPE_SYSTEM, None, None, byref(context)),
           "SCardEstablishContext")
    try:
        length = c_uint32(0)
        result = lib.SCardListReadersA(context, None, None, byref(length))
        _check(result, "SCardListReaders")
        buffer = create_string_buffer(length.value)
        _check(lib.SCardListReadersA(context, None, buffer, byref(length)), "SCardListReaders")
        readers = [item.decode(errors="replace") for item in buffer.raw.split(b"\0") if item]
        found = []
        for reader in readers:
            card = c_void_p()
            protocol = c_uint32()
            result = lib.SCardConnectA(context, c_char_p(reader.encode()), SCARD_SHARE_SHARED,
                                       SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                                       byref(card), byref(protocol))
            unsigned = ctypes.c_uint32(result).value
            if unsigned in (SCARD_E_NO_SMARTCARD, SCARD_W_REMOVED_CARD):
                found.append(TokenInfo(reader, "", "—", "Карта не вставлена", "EMPTY"))
                continue
            if unsigned != SCARD_S_SUCCESS:
                found.append(TokenInfo(reader, "", "—", "Ошибка чтения", "ERROR",
                                       f"PC/SC 0x{unsigned:08X}"))
                continue
            try:
                reader_len = c_uint32(0)
                atr_len = c_uint32(64)
                atr = (ctypes.c_ubyte * 64)()
                state = c_uint32()
                active_protocol = c_uint32()
                status = lib.SCardStatusA(card, None, byref(reader_len), byref(state),
                                          byref(active_protocol), atr, byref(atr_len))
                _check(status, "SCardStatus")
                atr_bytes = bytes(atr[:atr_len.value])
                vendor, model = _classify(atr_bytes)
                found.append(TokenInfo(reader, atr_bytes.hex(" ").upper(), vendor, model, "READY"))
            finally:
                lib.SCardDisconnect(card, SCARD_LEAVE_CARD)
        return found
    finally:
        lib.SCardReleaseContext(context)
