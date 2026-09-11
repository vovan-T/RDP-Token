"""Read-only Windows certificate/container inventory for inserted Rutoken devices."""

import ctypes
import platform
import re

from core.certificate_fields import name_fields
from core.diagnostics import logger
from ctypes import wintypes


LOG = logger()

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
except ImportError:
    x509 = hashes = serialization = None


CERT_KEY_PROV_INFO_PROP_ID = 2
PP_UNIQUE_CONTAINER = 36
CRYPT_SILENT = 0x40
NCRYPT_SILENT_FLAG = 0x40
NCRYPT_READER_PROPERTY = "SmartCardReader"
PP_SMARTCARD_READER = 43

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
    reader = ""
    parameter_ids = []
    if info.rgProvParam:
        for index in range(int(info.cProvParam)):
            parameter = info.rgProvParam[index]
            parameter_ids.append(int(parameter.dwParam))
            if parameter.dwParam != PP_SMARTCARD_READER or not parameter.pbData:
                continue
            raw = bytes(parameter.pbData[:parameter.cbData]).rstrip(b"\0")
            if b"\0" in raw:
                reader = raw.decode("utf-16-le", errors="replace").rstrip("\0")
            else:
                reader = raw.decode("mbcs", errors="replace")
    return {
        "container": info.pwszContainerName or "",
        "provider": info.pwszProvName or "",
        "provider_type": int(info.dwProvType),
        "key_spec": int(info.dwKeySpec),
        "reader": reader,
        "parameter_ids": parameter_ids,
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


def _ncrypt_text_property(ncrypt, handle, name: str) -> str:
    size = wintypes.DWORD()
    status = ncrypt.NCryptGetProperty(
        handle, name, None, 0, ctypes.byref(size), 0
    )
    if status != 0 or not size.value:
        return ""
    buffer = (ctypes.c_ubyte * size.value)()
    status = ncrypt.NCryptGetProperty(
        handle, name, buffer, size.value, ctypes.byref(size), 0
    )
    if status != 0:
        return ""
    return bytes(buffer[:size.value]).decode("utf-16-le", errors="replace").rstrip("\0")


def _ksp_reader(ncrypt, provider_info: dict) -> str:
    if provider_info.get("provider_type") != 0:
        return ""
    provider = ctypes.c_void_p()
    status = ncrypt.NCryptOpenStorageProvider(
        ctypes.byref(provider), provider_info.get("provider"), 0
    )
    if status != 0:
        LOG.info(
            "NCrypt provider open failed: provider=%r status=0x%08X",
            provider_info.get("provider"), status & 0xFFFFFFFF,
        )
        return ""
    key = ctypes.c_void_p()
    try:
        status = ncrypt.NCryptOpenKey(
            provider, ctypes.byref(key), provider_info.get("container"),
            0, NCRYPT_SILENT_FLAG,
        )
        if status != 0:
            LOG.info(
                "NCrypt key open failed: provider=%r container=%r status=0x%08X",
                provider_info.get("provider"), provider_info.get("container"),
                status & 0xFFFFFFFF,
            )
            return ""
        return _ncrypt_text_property(ncrypt, key, NCRYPT_READER_PROPERTY).strip()
    finally:
        if key.value:
            ncrypt.NCryptFreeObject(key)
        ncrypt.NCryptFreeObject(provider)


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
        "certificate_pem": certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
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
    ncrypt = ctypes.WinDLL("ncrypt", use_last_error=True)
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
    ncrypt.NCryptOpenStorageProvider.argtypes = [ctypes.POINTER(ctypes.c_void_p),
                                                  wintypes.LPCWSTR, wintypes.DWORD]
    ncrypt.NCryptOpenStorageProvider.restype = wintypes.LONG
    ncrypt.NCryptOpenKey.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                                     wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    ncrypt.NCryptOpenKey.restype = wintypes.LONG
    ncrypt.NCryptGetProperty.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR, ctypes.c_void_p,
                                         wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                                         wintypes.DWORD]
    ncrypt.NCryptGetProperty.restype = wintypes.LONG
    ncrypt.NCryptFreeObject.argtypes = [ctypes.c_void_p]
    ncrypt.NCryptFreeObject.restype = wintypes.LONG

    store = crypt32.CertOpenSystemStoreW(None, "MY")
    if not store:
        raise OSError(ctypes.get_last_error(), "Не удалось открыть CurrentUser\\MY")
    result = {}
    enumerated = 0
    with_provider = 0
    matched = 0
    parse_errors = 0
    previous = None
    try:
        while True:
            context = crypt32.CertEnumCertificatesInStore(store, previous)
            if not context:
                break
            previous = context
            enumerated += 1
            provider_info = _provider_info(crypt32, context)
            if not provider_info:
                continue
            with_provider += 1
            unique = _unique_container(advapi32, provider_info)
            reader = provider_info.get("reader") or _ksp_reader(ncrypt, provider_info)
            serial = _rutoken_serial(unique)
            if not serial and not reader:
                LOG.info(
                    "Windows certificate skipped: provider=%r container=%r unique=%r reason=no-token-identity",
                    provider_info.get("provider"), provider_info.get("container"), unique,
                )
                LOG.info(
                    "Windows provider parameters: provider=%r ids=%s",
                    provider_info.get("provider"), provider_info.get("parameter_ids"),
                )
                continue
            matched += 1
            LOG.info(
                "Windows certificate matched: provider=%r reader=%r serial_suffix=%s",
                provider_info.get("provider"), reader, serial[-4:],
            )
            encoded = ctypes.string_at(context.contents.pbCertEncoded,
                                       context.contents.cbCertEncoded)
            try:
                details = _certificate_details(encoded, provider_info, unique)
            except Exception as exc:
                parse_errors += 1
                LOG.exception(
                    "Windows certificate parse failed: provider=%r serial_suffix=%s error=%s",
                    provider_info.get("provider"), serial[-4:], exc,
                )
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
            aliases = _serial_aliases(serial) if serial else set()
            if reader:
                aliases.add(f"reader:{reader}")
            for alias in aliases:
                result.setdefault(alias, []).extend((public_key, certificate))
    finally:
        crypt32.CertCloseStore(store, 0)
    LOG.info(
        "Windows MY inventory: enumerated=%d with_provider=%d rutoken_matched=%d parse_errors=%d groups=%d",
        enumerated, with_provider, matched, parse_errors, len(result),
    )
    return result
