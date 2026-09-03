import ctypes
import hashlib
import os
import platform
import uuid
from pathlib import Path

from adapters.pkcs11_inventory import _select_slot

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    x509 = serialization = rsa = NameOID = None


CKR_OK = 0
CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x191
CKR_USER_ALREADY_LOGGED_IN = 0x100
CKF_RW_SESSION = 0x2
CKF_SERIAL_SESSION = 0x4
CKU_USER = 1

CKM_RSA_PKCS_KEY_PAIR_GEN = 0x0
CKM_RSA_PKCS = 0x1
CKO_PUBLIC_KEY = 0x2
CKO_PRIVATE_KEY = 0x3
CKO_CERTIFICATE = 0x1
CKK_RSA = 0x0
CKC_X_509 = 0x0

CKA_CLASS = 0x0
CKA_TOKEN = 0x1
CKA_PRIVATE = 0x2
CKA_LABEL = 0x3
CKA_VALUE = 0x11
CKA_CERTIFICATE_TYPE = 0x80
CKA_ISSUER = 0x81
CKA_SERIAL_NUMBER = 0x82
CKA_KEY_TYPE = 0x100
CKA_SUBJECT = 0x101
CKA_ID = 0x102
CKA_SENSITIVE = 0x103
CKA_ENCRYPT = 0x104
CKA_DECRYPT = 0x105
CKA_SIGN = 0x108
CKA_VERIFY = 0x10A
CKA_MODULUS = 0x120
CKA_MODULUS_BITS = 0x121
CKA_PUBLIC_EXPONENT = 0x122
CKA_EXTRACTABLE = 0x162

CKM_SHA256_RSA_PKCS = 0x40
CKR_FUNCTION_NOT_SUPPORTED = 0x54


ERRORS = {
    0x5: "Общая ошибка PKCS#11",
    0x7: "Некорректные аргументы PKCS#11",
    0x30: "Ошибка устройства",
    0x31: "Недостаточно памяти на токене",
    0x54: "Функция не поддерживается этим токеном",
    0x68: "Ключ не разрешён для этой операции",
    0x70: "Механизм не поддерживается токеном",
    0x60: "Ключевой шаблон некорректен",
    0xA0: "Неверный PIN",
    0xA4: "PIN заблокирован",
    0xD0: "Шаблон ключа неполный",
    0xD1: "Параметры ключевого шаблона несовместимы",
    0xE2: "Токен защищён от записи",
    0x101: "Пользователь не вошёл на токен",
}


class CK_ATTRIBUTE(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("type", ctypes.c_ulong),
        ("pValue", ctypes.c_void_p),
        ("ulValueLen", ctypes.c_ulong),
    ]


class CK_MECHANISM(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("mechanism", ctypes.c_ulong),
        ("pParameter", ctypes.c_void_p),
        ("ulParameterLen", ctypes.c_ulong),
    ]


class CK_MECHANISM_INFO(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("ulMinKeySize", ctypes.c_ulong),
        ("ulMaxKeySize", ctypes.c_ulong),
        ("flags", ctypes.c_ulong),
    ]


def _check(operation: str, result: int) -> None:
    if result != CKR_OK:
        detail = ERRORS.get(result, f"PKCS#11 0x{result:08X}")
        raise RuntimeError(f"{operation}: {detail}")


def _module_for(model: str) -> Path:
    if platform.system() != "Windows":
        raise RuntimeError("Создание CSR на Rutoken сейчас поддерживается только в Windows")
    normalized = (model or "").upper()
    windows = Path(os.environ.get("WINDIR", r"C:\Windows"))
    if "LITE" in normalized or "RUTOKEN S" in normalized or "РУТОКЕН S" in normalized:
        module = windows / "System32" / "rtPKCS11.dll"
        family = "Rutoken Lite/S"
    elif "ECP" in normalized or "ЭЦП" in normalized:
        module = windows / "System32" / "rtPKCS11ECP.dll"
        family = "Rutoken ЭЦП"
    else:
        raise RuntimeError(f"Не определён тип Rutoken: {model or 'нет данных'}")
    if not module.is_file():
        raise RuntimeError(f"Для {family} не найдена штатная библиотека: {module}")
    return module


def supports_rutoken_sdk(model: str) -> bool:
    normalized = (model or "").upper()
    return any(marker in normalized for marker in (
        "LITE", "RUTOKEN S", "РУТОКЕН S", "ECP", "ЭЦП",
    ))


def rutoken_rsa_key_sizes(serial: str, model: str) -> tuple[int, ...]:
    """Возвращает реальные размеры RSA из CKM_RSA_PKCS_KEY_PAIR_GEN."""
    module = _module_for(model)
    library = ctypes.CDLL(str(module))
    library.C_Initialize.argtypes = [ctypes.c_void_p]
    library.C_Initialize.restype = ctypes.c_ulong
    library.C_Finalize.argtypes = [ctypes.c_void_p]
    library.C_Finalize.restype = ctypes.c_ulong
    library.C_GetMechanismInfo.argtypes = [ctypes.c_ulong, ctypes.c_ulong,
                                            ctypes.POINTER(CK_MECHANISM_INFO)]
    library.C_GetMechanismInfo.restype = ctypes.c_ulong
    initialized = int(library.C_Initialize(None))
    if initialized not in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED):
        _check("Инициализация Rutoken", initialized)
    initialized_here = initialized == CKR_OK
    try:
        _DirectTable = type("_DirectTable", (), {
            "C_GetSlotList": ctypes.cast(library.C_GetSlotList, ctypes.c_void_p).value,
            "C_GetTokenInfo": ctypes.cast(library.C_GetTokenInfo, ctypes.c_void_p).value,
        })
        slot = _select_slot(_DirectTable, serial)
        info = CK_MECHANISM_INFO()
        _check("Чтение возможностей RSA", int(library.C_GetMechanismInfo(
            slot, CKM_RSA_PKCS_KEY_PAIR_GEN, ctypes.byref(info))))
        supported = tuple(size for size in (2048, 3072, 4096)
                          if info.ulMinKeySize <= size <= info.ulMaxKeySize)
        return supported or (2048,)
    finally:
        if initialized_here:
            library.C_Finalize(None)


def _attribute(kind: int, value, keepalive: list) -> CK_ATTRIBUTE:
    if isinstance(value, bool):
        buffer = ctypes.c_ubyte(1 if value else 0)
    elif isinstance(value, int):
        buffer = ctypes.c_ulong(value)
    else:
        raw = bytes(value)
        buffer = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
    keepalive.append(buffer)
    return CK_ATTRIBUTE(kind, ctypes.cast(ctypes.byref(buffer), ctypes.c_void_p),
                        ctypes.sizeof(buffer))


def _strings(values: list[str]):
    encoded = [value.encode("utf-8") for value in values]
    return (ctypes.c_char_p * len(encoded))(*encoded), encoded


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(content)) + content


def _der_oid(value: str) -> bytes:
    parts = [int(part) for part in value.split(".")]
    if len(parts) < 2 or parts[0] not in (0, 1, 2) or (parts[0] < 2 and parts[1] >= 40):
        raise ValueError(f"Некорректный OID: {value}")
    encoded = bytearray([40 * parts[0] + parts[1]])
    for number in parts[2:]:
        chunks = [number & 0x7F]
        number >>= 7
        while number:
            chunks.append(0x80 | (number & 0x7F))
            number >>= 7
        encoded.extend(reversed(chunks))
    return _der(0x06, bytes(encoded))


def _der_integer(value: bytes) -> bytes:
    value = value.lstrip(b"\x00") or b"\x00"
    if value[0] & 0x80:
        value = b"\x00" + value
    return _der(0x02, value)


def _upn_general_names(upn: str) -> bytes:
    # 1.3.6.1.4.1.311.20.2.3, закодированный как ASN.1 OID.
    oid = bytes.fromhex("2B060104018237140203")
    value = _der(0x0C, upn.encode("utf-8"))
    another_name = _der(0x06, oid) + _der(0xA0, value)
    return _der(0x30, _der(0xA0, another_name))


def _subject_public_key_info(modulus: bytes, exponent: bytes) -> bytes:
    rsa_public_key = _der(0x30, _der_integer(modulus) + _der_integer(exponent))
    rsa_algorithm = _der(0x30, _der_oid("1.2.840.113549.1.1.1") + b"\x05\x00")
    return _der(0x30, rsa_algorithm + _der(0x03, b"\x00" + rsa_public_key))


def _extension(oid: str, value: bytes, critical: bool = False) -> bytes:
    body = _der_oid(oid)
    if critical:
        body += b"\x01\x01\xFF"
    return _der(0x30, body + _der(0x04, value))


_SUBJECT_OIDS = {
    "CN": "2.5.4.3", "O": "2.5.4.10", "OU": "2.5.4.11",
    "C": "2.5.4.6", "serialNumber": "2.5.4.5",
}


def _subject_der(subject_fields: dict[str, str]) -> bytes:
    rdns = []
    for name in ("CN", "O", "OU", "C", "serialNumber"):
        value = (subject_fields.get(name) or "").strip()
        if not value:
            continue
        tag = 0x13 if name == "C" else 0x0C
        attribute = _der(0x30, _der_oid(_SUBJECT_OIDS[name])
                         + _der(tag, value.encode("ascii" if name == "C" else "utf-8")))
        rdns.append(_der(0x31, attribute))
    if not rdns:
        raise RuntimeError("Subject CSR пустой")
    return _der(0x30, b"".join(rdns))


def _certification_request_info(subject_fields: dict[str, str], upn: str,
                                modulus: bytes, exponent: bytes) -> bytes:
    subject = _subject_der(subject_fields)
    extensions = [
        _extension("2.5.29.15", _der(0x03, b"\x05\xA0"), critical=True),
        _extension("2.5.29.37", _der(0x30,
            _der_oid("1.3.6.1.5.5.7.3.2") + _der_oid("1.3.6.1.4.1.311.20.2.2"))),
    ]
    if upn:
        extensions.append(_extension("2.5.29.17", _upn_general_names(upn)))
    extension_request = _der(0x30,
        _der_oid("1.2.840.113549.1.9.14") + _der(0x31, _der(0x30, b"".join(extensions))))
    attributes = _der(0xA0, extension_request)
    return _der(0x30, b"\x02\x01\x00" + subject
                + _subject_public_key_info(modulus, exponent) + attributes)


def _read_attributes(library, session: int, object_handle: int,
                     attribute_types: tuple[int, ...]) -> list[bytes]:
    attributes = (CK_ATTRIBUTE * len(attribute_types))(*(
        CK_ATTRIBUTE(kind, None, 0) for kind in attribute_types
    ))
    _check("Чтение размеров открытого ключа", int(library.C_GetAttributeValue(
        session, object_handle, attributes, len(attributes))))
    buffers = []
    for attribute in attributes:
        buffer = (ctypes.c_ubyte * attribute.ulValueLen)()
        buffers.append(buffer)
        attribute.pValue = ctypes.cast(buffer, ctypes.c_void_p)
    _check("Чтение открытого ключа", int(library.C_GetAttributeValue(
        session, object_handle, attributes, len(attributes))))
    return [bytes(buffer) for buffer in buffers]


def _sign(library, session: int, private_key: int, data: bytes) -> bytes:
    mechanism = CK_MECHANISM(CKM_SHA256_RSA_PKCS, None, 0)
    sign_data = data
    initialized = int(library.C_SignInit(session, ctypes.byref(mechanism), private_key))
    if initialized == 0x70:
        # Rutoken Lite не выполняет SHA-256 внутри токена, но поддерживает
        # стандартную RSA PKCS#1 v1.5 подпись готового DigestInfo.
        mechanism = CK_MECHANISM(CKM_RSA_PKCS, None, 0)
        _check("Подготовка RSA-подписи CSR", int(library.C_SignInit(
            session, ctypes.byref(mechanism), private_key)))
        sha256_digest_info = bytes.fromhex(
            "3031300D060960864801650304020105000420")
        sign_data = sha256_digest_info + hashlib.sha256(data).digest()
    else:
        _check("Подготовка подписи CSR", initialized)
    data_buffer = (ctypes.c_ubyte * len(sign_data)).from_buffer_copy(sign_data)
    signature_length = ctypes.c_ulong()
    _check("Расчёт размера подписи CSR", int(library.C_Sign(
        session, data_buffer, len(sign_data), None, ctypes.byref(signature_length))))
    signature = (ctypes.c_ubyte * signature_length.value)()
    _check("Подпись CSR", int(library.C_Sign(
        session, data_buffer, len(sign_data), signature, ctypes.byref(signature_length))))
    return bytes(signature[:signature_length.value])


def _create_standard_csr(library, session: int, public_key: int, private_key: int,
                         subject_fields: dict[str, str], upn: str) -> bytes:
    modulus, exponent = _read_attributes(
        library, session, public_key, (CKA_MODULUS, CKA_PUBLIC_EXPONENT))
    request_info = _certification_request_info(subject_fields, upn, modulus, exponent)
    signature = _sign(library, session, private_key, request_info)
    signature_algorithm = _der(0x30, _der_oid("1.2.840.113549.1.1.11") + b"\x05\x00")
    return _der(0x30, request_info + signature_algorithm + _der(0x03, b"\x00" + signature))


def _destroy_quietly(destroy, session: int, handle: int) -> None:
    if handle:
        destroy(session, handle)


def _matching_public_key(library, session: int, modulus: bytes) -> tuple[int, bytes]:
    keepalive = []
    template = (CK_ATTRIBUTE * 1)(
        _attribute(CKA_CLASS, CKO_PUBLIC_KEY, keepalive),
    )
    _check("Поиск открытых ключей", int(library.C_FindObjectsInit(
        session, template, len(template))))
    wanted = int.from_bytes(modulus, "big")
    try:
        while True:
            handles = (ctypes.c_ulong * 16)()
            count = ctypes.c_ulong()
            _check("Чтение открытых ключей", int(library.C_FindObjects(
                session, handles, len(handles), ctypes.byref(count))))
            if not count.value:
                break
            for handle in handles[:count.value]:
                try:
                    candidate_modulus, key_id = _read_attributes(
                        library, session, handle, (CKA_MODULUS, CKA_ID))
                except RuntimeError:
                    continue
                if int.from_bytes(candidate_modulus, "big") == wanted:
                    return handle, key_id
    finally:
        library.C_FindObjectsFinal(session)
    raise RuntimeError(
        "В выбранном токене не найден ключ, соответствующий сертификату. "
        "Проверь, что устанавливается сертификат именно от этого CSR.")


def _find_object_by_id(library, session: int, object_class: int, key_id: bytes) -> int:
    keepalive = []
    template = (CK_ATTRIBUTE * 2)(
        _attribute(CKA_CLASS, object_class, keepalive),
        _attribute(CKA_ID, key_id, keepalive),
    )
    _check("Поиск связанного объекта", int(library.C_FindObjectsInit(
        session, template, len(template))))
    try:
        handle = ctypes.c_ulong()
        count = ctypes.c_ulong()
        _check("Чтение связанного объекта", int(library.C_FindObjects(
            session, ctypes.byref(handle), 1, ctypes.byref(count))))
        return handle.value if count.value else 0
    finally:
        library.C_FindObjectsFinal(session)


def _set_object_label(library, session: int, handle: int, label_text: str) -> None:
    if not handle:
        return
    label = label_text.encode("utf-8")
    if len(label) > 64:
        raise RuntimeError("Название объекта длиннее 64 байт UTF-8")
    keepalive = []
    attribute = (CK_ATTRIBUTE * 1)(_attribute(CKA_LABEL, label, keepalive))
    _check("Запись названия объекта", int(library.C_SetAttributeValue(
        session, handle, attribute, len(attribute))))


def install_rutoken_certificate(serial: str, model: str, token_label: str,
                                certificate_path: Path, pin: str,
                                key_label: str = "", certificate_label: str = "") -> None:
    if x509 is None or serialization is None or rsa is None:
        raise RuntimeError("В клиенте отсутствует модуль разбора X.509")
    if not certificate_path.is_file():
        raise RuntimeError("Файл сертификата не найден")
    raw = certificate_path.read_bytes()
    try:
        certificate = x509.load_pem_x509_certificate(raw)
    except ValueError:
        try:
            certificate = x509.load_der_x509_certificate(raw)
        except ValueError as exc:
            raise RuntimeError("Файл не содержит сертификат X.509 в PEM или DER") from exc
    public_key = certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise RuntimeError("Сейчас установка на Rutoken поддерживает RSA-сертификаты")

    module = _module_for(model)
    library = ctypes.CDLL(str(module))
    library.C_Initialize.argtypes = [ctypes.c_void_p]
    library.C_Initialize.restype = ctypes.c_ulong
    library.C_Finalize.argtypes = [ctypes.c_void_p]
    library.C_Finalize.restype = ctypes.c_ulong
    library.C_OpenSession.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p,
                                      ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    library.C_OpenSession.restype = ctypes.c_ulong
    library.C_CloseSession.argtypes = [ctypes.c_ulong]
    library.C_CloseSession.restype = ctypes.c_ulong
    library.C_Login.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p,
                                ctypes.c_ulong]
    library.C_Login.restype = ctypes.c_ulong
    library.C_Logout.argtypes = [ctypes.c_ulong]
    library.C_Logout.restype = ctypes.c_ulong
    library.C_GetAttributeValue.argtypes = [ctypes.c_ulong, ctypes.c_ulong,
                                             ctypes.POINTER(CK_ATTRIBUTE), ctypes.c_ulong]
    library.C_GetAttributeValue.restype = ctypes.c_ulong
    library.C_FindObjectsInit.argtypes = [ctypes.c_ulong, ctypes.POINTER(CK_ATTRIBUTE),
                                           ctypes.c_ulong]
    library.C_FindObjectsInit.restype = ctypes.c_ulong
    library.C_FindObjects.argtypes = [ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong),
                                       ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    library.C_FindObjects.restype = ctypes.c_ulong
    library.C_FindObjectsFinal.argtypes = [ctypes.c_ulong]
    library.C_FindObjectsFinal.restype = ctypes.c_ulong
    library.C_CreateObject.argtypes = [ctypes.c_ulong, ctypes.POINTER(CK_ATTRIBUTE),
                                        ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
    library.C_CreateObject.restype = ctypes.c_ulong
    library.C_SetAttributeValue.argtypes = [ctypes.c_ulong, ctypes.c_ulong,
                                             ctypes.POINTER(CK_ATTRIBUTE), ctypes.c_ulong]
    library.C_SetAttributeValue.restype = ctypes.c_ulong

    initialized = int(library.C_Initialize(None))
    if initialized not in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED):
        _check("Инициализация Rutoken", initialized)
    initialized_here = initialized == CKR_OK
    session = ctypes.c_ulong()
    try:
        _DirectTable = type("_DirectTable", (), {
            "C_GetSlotList": ctypes.cast(library.C_GetSlotList, ctypes.c_void_p).value,
            "C_GetTokenInfo": ctypes.cast(library.C_GetTokenInfo, ctypes.c_void_p).value,
        })
        slot = _select_slot(_DirectTable, serial)
        _check("Открытие выбранного Rutoken", int(library.C_OpenSession(
            slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(session))))
        pin_bytes = bytearray(pin.encode("utf-8"))
        pin_buffer = (ctypes.c_ubyte * len(pin_bytes)).from_buffer(pin_bytes)
        logged_in = int(library.C_Login(session.value, CKU_USER,
                                        ctypes.cast(pin_buffer, ctypes.c_void_p), len(pin_bytes)))
        for index in range(len(pin_bytes)):
            pin_bytes[index] = 0
        if logged_in not in (CKR_OK, CKR_USER_ALREADY_LOGGED_IN):
            _check("Вход по PIN", logged_in)

        numbers = public_key.public_numbers()
        modulus = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
        public_handle, key_id = _matching_public_key(library, session.value, modulus)
        common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        default_label = common_names[0].value if common_names else (token_label or "Certificate")
        label_text = certificate_label.strip() or default_label
        key_label_text = key_label.strip() or default_label
        label = label_text.encode("utf-8")[:64]
        value = certificate.public_bytes(serialization.Encoding.DER)
        subject = certificate.subject.public_bytes()
        issuer = certificate.issuer.public_bytes()
        serial_bytes = certificate.serial_number.to_bytes(
            max(1, (certificate.serial_number.bit_length() + 7) // 8), "big")
        serial_der = _der_integer(serial_bytes)
        keepalive = []
        template = (CK_ATTRIBUTE * 10)(
            _attribute(CKA_CLASS, CKO_CERTIFICATE, keepalive),
            _attribute(CKA_TOKEN, True, keepalive),
            _attribute(CKA_PRIVATE, False, keepalive),
            _attribute(CKA_CERTIFICATE_TYPE, CKC_X_509, keepalive),
            _attribute(CKA_LABEL, label, keepalive),
            _attribute(CKA_ID, key_id, keepalive),
            _attribute(CKA_SUBJECT, subject, keepalive),
            _attribute(CKA_ISSUER, issuer, keepalive),
            _attribute(CKA_SERIAL_NUMBER, serial_der, keepalive),
            _attribute(CKA_VALUE, value, keepalive),
        )
        certificate_handle = ctypes.c_ulong()
        _check("Запись сертификата в Rutoken", int(library.C_CreateObject(
            session.value, template, len(template), ctypes.byref(certificate_handle))))
        _set_object_label(library, session.value, public_handle, key_label_text)
        private_handle = _find_object_by_id(library, session.value, CKO_PRIVATE_KEY, key_id)
        _set_object_label(library, session.value, private_handle, key_label_text)
    finally:
        if session.value:
            library.C_Logout(session.value)
            library.C_CloseSession(session.value)
        if initialized_here:
            library.C_Finalize(None)


def create_rutoken_request(serial: str, model: str, key_label: str,
                           common_name: str, upn: str, key_length: int,
                           pin: str, request_path: Path,
                           subject_fields: dict[str, str] | None = None) -> Path:
    if key_length not in (2048, 3072, 4096):
        raise RuntimeError("Для Rutoken доступны RSA 2048, 3072 и 4096")
    module = _module_for(model)
    library = ctypes.CDLL(str(module))

    library.C_Initialize.argtypes = [ctypes.c_void_p]
    library.C_Initialize.restype = ctypes.c_ulong
    library.C_Finalize.argtypes = [ctypes.c_void_p]
    library.C_Finalize.restype = ctypes.c_ulong
    library.C_OpenSession.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p,
                                      ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    library.C_OpenSession.restype = ctypes.c_ulong
    library.C_CloseSession.argtypes = [ctypes.c_ulong]
    library.C_CloseSession.restype = ctypes.c_ulong
    library.C_Login.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p,
                                ctypes.c_ulong]
    library.C_Login.restype = ctypes.c_ulong
    library.C_Logout.argtypes = [ctypes.c_ulong]
    library.C_Logout.restype = ctypes.c_ulong
    library.C_DestroyObject.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
    library.C_DestroyObject.restype = ctypes.c_ulong
    library.C_GenerateKeyPair.argtypes = [ctypes.c_ulong, ctypes.POINTER(CK_MECHANISM),
                                          ctypes.POINTER(CK_ATTRIBUTE), ctypes.c_ulong,
                                          ctypes.POINTER(CK_ATTRIBUTE), ctypes.c_ulong,
                                          ctypes.POINTER(ctypes.c_ulong),
                                          ctypes.POINTER(ctypes.c_ulong)]
    library.C_GenerateKeyPair.restype = ctypes.c_ulong
    library.C_GetAttributeValue.argtypes = [ctypes.c_ulong, ctypes.c_ulong,
                                             ctypes.POINTER(CK_ATTRIBUTE), ctypes.c_ulong]
    library.C_GetAttributeValue.restype = ctypes.c_ulong
    library.C_SignInit.argtypes = [ctypes.c_ulong, ctypes.POINTER(CK_MECHANISM),
                                    ctypes.c_ulong]
    library.C_SignInit.restype = ctypes.c_ulong
    library.C_Sign.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong,
                                ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    library.C_Sign.restype = ctypes.c_ulong
    library.C_EX_CreateCSR.argtypes = [
        ctypes.c_ulong, ctypes.c_ulong, ctypes.POINTER(ctypes.c_char_p), ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_ulong), ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_char_p), ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_char_p), ctypes.c_ulong,
    ]
    library.C_EX_CreateCSR.restype = ctypes.c_ulong
    library.C_EX_FreeBuffer.argtypes = [ctypes.c_void_p]
    library.C_EX_FreeBuffer.restype = ctypes.c_ulong

    initialized = int(library.C_Initialize(None))
    if initialized not in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED):
        _check("Инициализация Rutoken", initialized)
    initialized_here = initialized == CKR_OK
    session = ctypes.c_ulong()
    public_key = ctypes.c_ulong()
    private_key = ctypes.c_ulong()
    generated = False
    try:
        # Используем общий проверенный выбор слота по серийному номеру.
        _DirectTable = type("_DirectTable", (), {
            "C_GetSlotList": ctypes.cast(library.C_GetSlotList, ctypes.c_void_p).value,
            "C_GetTokenInfo": ctypes.cast(library.C_GetTokenInfo, ctypes.c_void_p).value,
        })
        slot = _select_slot(_DirectTable, serial)
        _check("Открытие выбранного Rutoken", int(library.C_OpenSession(
            slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None, ctypes.byref(session))))
        pin_bytes = bytearray(pin.encode("utf-8"))
        pin_buffer = (ctypes.c_ubyte * len(pin_bytes)).from_buffer(pin_bytes)
        logged_in = int(library.C_Login(session.value, CKU_USER,
                                        ctypes.cast(pin_buffer, ctypes.c_void_p), len(pin_bytes)))
        for index in range(len(pin_bytes)):
            pin_bytes[index] = 0
        if logged_in not in (CKR_OK, CKR_USER_ALREADY_LOGGED_IN):
            _check("Вход по PIN", logged_in)

        key_id = uuid.uuid4().bytes
        label = (key_label or f"RDP-Token-{serial}").encode("utf-8")[:64]
        exponent = b"\x01\x00\x01"
        public_keepalive, private_keepalive = [], []
        public_template = (CK_ATTRIBUTE * 10)(
            _attribute(CKA_CLASS, CKO_PUBLIC_KEY, public_keepalive),
            _attribute(CKA_ID, key_id, public_keepalive),
            _attribute(CKA_LABEL, label, public_keepalive),
            _attribute(CKA_KEY_TYPE, CKK_RSA, public_keepalive),
            _attribute(CKA_TOKEN, True, public_keepalive),
            _attribute(CKA_PRIVATE, False, public_keepalive),
            _attribute(CKA_ENCRYPT, True, public_keepalive),
            _attribute(CKA_VERIFY, True, public_keepalive),
            _attribute(CKA_MODULUS_BITS, key_length, public_keepalive),
            _attribute(CKA_PUBLIC_EXPONENT, exponent, public_keepalive),
        )
        private_template = (CK_ATTRIBUTE * 10)(
            _attribute(CKA_CLASS, CKO_PRIVATE_KEY, private_keepalive),
            _attribute(CKA_ID, key_id, private_keepalive),
            _attribute(CKA_LABEL, label, private_keepalive),
            _attribute(CKA_KEY_TYPE, CKK_RSA, private_keepalive),
            _attribute(CKA_TOKEN, True, private_keepalive),
            _attribute(CKA_PRIVATE, True, private_keepalive),
            _attribute(CKA_SENSITIVE, True, private_keepalive),
            _attribute(CKA_DECRYPT, True, private_keepalive),
            _attribute(CKA_SIGN, True, private_keepalive),
            _attribute(CKA_EXTRACTABLE, False, private_keepalive),
        )
        mechanism = CK_MECHANISM(CKM_RSA_PKCS_KEY_PAIR_GEN, None, 0)
        _check("Создание RSA-ключа", int(library.C_GenerateKeyPair(
            session.value, ctypes.byref(mechanism), public_template, len(public_template),
            private_template, len(private_template), ctypes.byref(public_key),
            ctypes.byref(private_key))))
        generated = True

        subject_fields = dict(subject_fields or {})
        subject_fields["CN"] = common_name
        dn_values = []
        for name in ("CN", "O", "OU", "C", "serialNumber"):
            value = (subject_fields.get(name) or "").strip()
            if value:
                value_type = "PrintableString" if name == "C" else "UTF8String"
                dn_values.extend([_SUBJECT_OIDS[name], f"{value_type}:{value}"])
        dn, dn_keepalive = _strings(dn_values)
        extensions = [
            "keyUsage", "digitalSignature,keyEncipherment",
            "extendedKeyUsage", "1.3.6.1.5.5.7.3.2,1.3.6.1.4.1.311.20.2.2",
        ]
        if upn:
            der = ":".join(f"{byte:02X}" for byte in _upn_general_names(upn))
            extensions.extend(["2.5.29.17", f"DER:{der}"])
        extension_array, extension_keepalive = _strings(extensions)
        csr_pointer = ctypes.c_void_p()
        csr_length = ctypes.c_ulong()
        result = int(library.C_EX_CreateCSR(
            session.value, public_key.value, dn, len(dn), ctypes.byref(csr_pointer),
            ctypes.byref(csr_length), private_key.value, None, 0,
            extension_array, len(extensions)))
        if result == CKR_FUNCTION_NOT_SUPPORTED:
            csr = _create_standard_csr(
                library, session.value, public_key.value, private_key.value,
                subject_fields, upn)
        else:
            _check("Создание PKCS#10 CSR", result)
            try:
                csr = ctypes.string_at(csr_pointer, csr_length.value)
            finally:
                library.C_EX_FreeBuffer(csr_pointer)
        request_path.parent.mkdir(parents=True, exist_ok=True)
        request_path.write_bytes(csr)
        return request_path
    except Exception:
        if generated and session.value:
            _destroy_quietly(library.C_DestroyObject, session.value, private_key.value)
            _destroy_quietly(library.C_DestroyObject, session.value, public_key.value)
        raise
    finally:
        if session.value:
            library.C_Logout(session.value)
            library.C_CloseSession(session.value)
        if initialized_here:
            library.C_Finalize(None)
