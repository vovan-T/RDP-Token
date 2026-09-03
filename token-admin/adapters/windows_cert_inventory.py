"""Read-only Windows certificate/container inventory for inserted Rutoken devices."""

import ctypes
import platform
import re

from core.certificate_fields import name_fields
from ctypes import wintypes

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
except ImportError:
    x509 = hashes = None


CERT_KEY_PROV_INFO_PROP_ID = 2
PP_UNIQUE_CONTAINER = 36
CRYPT_SILENT = 0x40

PUBLIC_KEY_NAMES = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.10045.2.1": "ECDSA",
    "1.2.643.2.2.19": "GOST R 34.10-2001",
    "1.2.643.7.1.1.1.1": "GOST R 34.10-2012 256",
    "1.2.643.7.1.1.1.2": "GOST R 34.10-2012 512",
}


class CERT_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("dwCertEncodingType", wintypes.DWORD),
        ("pbCertEncoded", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbCertEncoded", wintypes.DWORD),
        ("pCertInfo", ctypes.c_void_p),
        ("hCertStore", ctypes.c_void_p),
    ]


class CRYPT_KEY_PROV_PARAM(ctypes.Structure):
    _fields_ = [
        ("dwParam", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbData", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
    ]


class CRYPT_KEY_PROV_INFO(ctypes.Structure):
    _fields_ = [
        ("pwszContainerName", wintypes.LPWSTR),
        ("pwszProvName", wintypes.LPWSTR),
        ("dwProvType", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("cProvParam", wintypes.DWORD),
        ("rgProvParam", ctypes.POINTER(CRYPT_KEY_PROV_PARAM)),
        ("dwKeySpec", wintypes.DWORD),
    ]


def _serial_aliases(value: str) -> set[str]:
    normalized = "".join(char for char in value.upper() if char.isalnum()).lstrip("0") or "0"
    aliases = {normalized}
    try:
        if normalized.isdigit():
            aliases.add(f"{int(normalized):X}")
        elif all(char in "0123456789ABCDEF" for char in normalized):
            aliases.add(str(int(normalized, 16)))
    except ValueError:
        pass
    return aliases


def _property(crypt32, context, property_id: int) -> bytes:
    size = wintypes.DWORD()
    if not crypt32.CertGetCertificateContextProperty(context, property_id, None, ctypes.byref(size)):
        return b""
    buffer = ctypes.create_string_buffer(size.value)
    if not crypt32.CertGetCertificateContextProperty(
            context, property_id, buffer, ctypes.byref(size)):
        return b""
    return buffer.raw[:size.value]


def _provider_info(crypt32, context):
    size = wintypes.DWORD()
    if not crypt32.CertGetCertificateContextProperty(
            context, CERT_KEY_PROV_INFO_PROP_ID, None, ctypes.byref(size)):
        return None
    buffer = ctypes.create_string_buffer(size.value)
    if not crypt32.CertGetCertificateContextProperty(
            context, CERT_KEY_PROV_INFO_PROP_ID, buffer, ctypes.byref(size)):
        return None
    info = ctypes.cast(buffer, ctypes.POINTER(CRYPT_KEY_PROV_INFO)).contents
    return {
        "container": info.pwszContainerName or "",
        "provider": info.pwszProvName or "",
        "provider_type": int(info.dwProvType),
        "key_spec": int(info.dwKeySpec),
    }


def _unique_container(advapi32, provider_info: dict) -> str:
    if not provider_info.get("provider_type"):
        return ""
    handle = ctypes.c_void_p()
    acquired = advapi32.CryptAcquireContextW(
        ctypes.byref(handle), provider_info.get("container"), provider_info.get("provider"),
        provider_info["provider_type"], CRYPT_SILENT)
    if not acquired:
        return ""
    try:
        size = wintypes.DWORD()
        if not advapi32.CryptGetProvParam(handle, PP_UNIQUE_CONTAINER, None,
                                          ctypes.byref(size), 0):
            return ""
        buffer = (ctypes.c_ubyte * size.value)()
        if not advapi32.CryptGetProvParam(handle, PP_UNIQUE_CONTAINER, buffer,
                                          ctypes.byref(size), 0):
            return ""
        raw = bytes(buffer[:size.value]).rstrip(b"\0")
        return raw.decode("mbcs", errors="replace")
    finally:
        advapi32.CryptReleaseContext(handle, 0)


def _rutoken_serial(unique_container: str) -> str:
    match = re.search(r"rutoken(?:_ecp)?_([0-9a-f]+)", unique_container, re.IGNORECASE)
    return match.group(1) if match else ""


def _certificate_details(encoded: bytes, provider_info: dict, unique_container: str) -> dict:
    if not encoded or x509 is None:
        return {}
    certificate = x509.load_der_x509_certificate(encoded)
    oid = certificate.public_key_algorithm_oid.dotted_string
    key_type = PUBLIC_KEY_NAMES.get(oid, oid)
    if key_type == "RSA":
        try:
            key_type = f"RSA {certificate.public_key().key_size}"
        except Exception:
            pass
    fingerprint = certificate.fingerprint(hashes.SHA1()).hex().upper()
    subject = certificate.subject.rfc4514_string()
    common_names = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    label = common_names[0].value if common_names else subject
    return {
        "label": label,
        "subject": subject,
        "subject_fields": name_fields(certificate.subject),
        "issuer": certificate.issuer.rfc4514_string(),
        "issuer_fields": name_fields(certificate.issuer),
        "serial": f"{certificate.serial_number:X}",
        "key_type": key_type,
        "not_before_date": certificate.not_valid_before_utc.strftime("%d.%m.%Y %H:%M UTC"),
        "not_after_date": certificate.not_valid_after_utc.strftime("%d.%m.%Y %H:%M UTC"),
        "fingerprint": fingerprint,
        "fingerprint_sha256": certificate.fingerprint(hashes.SHA256()).hex().upper(),
        "provider": provider_info.get("provider", ""),
        "container": provider_info.get("container", ""),
        "unique_container": unique_container,
        "source": "Windows CSP/KSP",
    }


def read_windows_rutoken_objects() -> dict[str, list[dict]]:
    """Return public certificate/key metadata for currently accessible Rutoken containers."""
    if platform.system() != "Windows" or x509 is None:
        return {}

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    crypt32.CertOpenSystemStoreW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    crypt32.CertOpenSystemStoreW.restype = ctypes.c_void_p
    crypt32.CertEnumCertificatesInStore.argtypes = [ctypes.c_void_p,
                                                     ctypes.POINTER(CERT_CONTEXT)]
    crypt32.CertEnumCertificatesInStore.restype = ctypes.POINTER(CERT_CONTEXT)
    crypt32.CertGetCertificateContextProperty.argtypes = [ctypes.POINTER(CERT_CONTEXT),
                                                           wintypes.DWORD, ctypes.c_void_p,
                                                           ctypes.POINTER(wintypes.DWORD)]
    crypt32.CertGetCertificateContextProperty.restype = wintypes.BOOL
    crypt32.CertCloseStore.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    crypt32.CertCloseStore.restype = wintypes.BOOL
    advapi32.CryptAcquireContextW.argtypes = [ctypes.POINTER(ctypes.c_void_p), wintypes.LPCWSTR,
                                              wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    advapi32.CryptAcquireContextW.restype = wintypes.BOOL
    advapi32.CryptGetProvParam.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p,
                                           ctypes.POINTER(wintypes.DWORD), wintypes.DWORD]
    advapi32.CryptGetProvParam.restype = wintypes.BOOL
    advapi32.CryptReleaseContext.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    advapi32.CryptReleaseContext.restype = wintypes.BOOL

    store = crypt32.CertOpenSystemStoreW(None, "MY")
    if not store:
        raise OSError(ctypes.get_last_error(), "Не удалось открыть CurrentUser\\MY")
    result = {}
    previous = None
    try:
        while True:
            context = crypt32.CertEnumCertificatesInStore(store, previous)
            if not context:
                break
            previous = context
            provider_info = _provider_info(crypt32, context)
            if not provider_info:
                continue
            unique = _unique_container(advapi32, provider_info)
            serial = _rutoken_serial(unique)
            if not serial:
                continue
            encoded = ctypes.string_at(context.contents.pbCertEncoded,
                                       context.contents.cbCertEncoded)
            try:
                details = _certificate_details(encoded, provider_info, unique)
            except Exception:
                continue
            if not details:
                continue
            certificate = {
                **details,
                "type": "Сертификат",
                "id": provider_info["container"] or details["fingerprint"],
            }
            public_key = {
                "type": "Открытый ключ",
                "label": details["label"],
                "id": certificate["id"],
                "key_type": details["key_type"],
                "usage": "VERIFY",
                "fingerprint": details["fingerprint"],
                "provider": details["provider"],
                "container": details["container"],
                "unique_container": details["unique_container"],
                "source": details["source"],
            }
            for alias in _serial_aliases(serial):
                result.setdefault(alias, []).extend((public_key, certificate))
    finally:
        crypt32.CertCloseStore(store, 0)
    return result
