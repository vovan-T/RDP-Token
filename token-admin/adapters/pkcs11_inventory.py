import ctypes
import os
import platform
from pathlib import Path

from core.certificate_fields import name_fields
from adapters.tool_paths import lib_file

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
except ImportError:
    x509 = hashes = serialization = ec = rsa = None


CKR_OK = 0
CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x191
CKF_SERIAL_SESSION = 0x4
CKF_RW_SESSION = 0x2
CKU_USER = 1
CKU_SO = 0
CKR_USER_ALREADY_LOGGED_IN = 0x100
CKA_CLASS = 0x0
CKA_LABEL = 0x3
CKA_VALUE = 0x11
CKA_KEY_TYPE = 0x100
CKA_ID = 0x102
CKA_ENCRYPT = 0x104
CKA_SIGN = 0x108
CKA_VERIFY = 0x10A
CKA_DERIVE = 0x10C
CKA_MODULUS_BITS = 0x121

KEY_TYPES = {
    0x0: "RSA", 0x1: "DSA", 0x2: "DH", 0x3: "ECDSA", 0x30: "GOST R 34.10",
}

OBJECT_TYPES = {
    0x0: "Данные", 0x1: "Сертификат", 0x2: "Открытый ключ",
    0x3: "Закрытый ключ", 0x4: "Секретный ключ",
}

LOGIN_ERRORS = {
    0xA0: "Неверный PIN",
    0xA1: "PIN недействителен",
    0xA2: "Недопустимая длина PIN",
    0xA3: "Срок действия PIN истёк",
    0xA4: "PIN заблокирован",
}


class CK_VERSION(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("major", ctypes.c_ubyte), ("minor", ctypes.c_ubyte)]


class CK_FUNCTION_LIST(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("version", CK_VERSION)] + [(name, ctypes.c_void_p) for name in (
        "C_Initialize", "C_Finalize", "C_GetInfo", "C_GetFunctionList",
        "C_GetSlotList", "C_GetSlotInfo", "C_GetTokenInfo", "C_GetMechanismList",
        "C_GetMechanismInfo", "C_InitToken", "C_InitPIN", "C_SetPIN",
        "C_OpenSession", "C_CloseSession", "C_CloseAllSessions", "C_GetSessionInfo",
        "C_GetOperationState", "C_SetOperationState", "C_Login", "C_Logout",
        "C_CreateObject", "C_CopyObject", "C_DestroyObject", "C_GetObjectSize",
        "C_GetAttributeValue", "C_SetAttributeValue", "C_FindObjectsInit",
        "C_FindObjects", "C_FindObjectsFinal",
    )]


class CK_ATTRIBUTE(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("type", ctypes.c_ulong), ("pValue", ctypes.c_void_p),
                ("ulValueLen", ctypes.c_ulong)]


class CK_TOKEN_INFO(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("label", ctypes.c_ubyte * 32), ("manufacturerID", ctypes.c_ubyte * 32),
        ("model", ctypes.c_ubyte * 16), ("serialNumber", ctypes.c_ubyte * 16),
        ("flags", ctypes.c_ulong), ("ulMaxSessionCount", ctypes.c_ulong),
        ("ulSessionCount", ctypes.c_ulong), ("ulMaxRwSessionCount", ctypes.c_ulong),
        ("ulRwSessionCount", ctypes.c_ulong), ("ulMaxPinLen", ctypes.c_ulong),
        ("ulMinPinLen", ctypes.c_ulong), ("ulTotalPublicMemory", ctypes.c_ulong),
        ("ulFreePublicMemory", ctypes.c_ulong), ("ulTotalPrivateMemory", ctypes.c_ulong),
        ("ulFreePrivateMemory", ctypes.c_ulong), ("hardwareVersion", CK_VERSION),
        ("firmwareVersion", CK_VERSION), ("utcTime", ctypes.c_ubyte * 16),
    ]


class CK_SLOT_INFO(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("slotDescription", ctypes.c_ubyte * 64),
        ("manufacturerID", ctypes.c_ubyte * 32),
        ("flags", ctypes.c_ulong),
        ("hardwareVersion", CK_VERSION),
        ("firmwareVersion", CK_VERSION),
    ]


def _function(pointer, *arguments):
    return ctypes.CFUNCTYPE(ctypes.c_ulong, *arguments)(pointer)


def _attribute(get_attributes, session, handle, kind):
    attribute = CK_ATTRIBUTE(kind, None, 0)
    result = int(get_attributes(session, handle, ctypes.byref(attribute), 1))
    if result != CKR_OK or attribute.ulValueLen in (0, 0xFFFFFFFF):
        return b""
    buffer = (ctypes.c_ubyte * attribute.ulValueLen)()
    attribute.pValue = ctypes.cast(buffer, ctypes.c_void_p)
    result = int(get_attributes(session, handle, ctypes.byref(attribute), 1))
    return bytes(buffer) if result == CKR_OK else b""


def _display_id(value: bytes) -> str:
    if value and all(32 <= byte <= 126 for byte in value):
        return value.decode("ascii")
    return value.hex().upper() or "—"


def _ulong(value: bytes):
    return int.from_bytes(value, "little") if value else None


def _enabled(value: bytes) -> bool:
    return bool(value and value[0])


def _usage(get_attributes, session, handle) -> str:
    names = []
    for attribute, name in (
        (CKA_SIGN, "SIGN"), (CKA_VERIFY, "VERIFY"),
        (CKA_ENCRYPT, "ENCRYPT"), (CKA_DERIVE, "DERIVE"),
    ):
        if _enabled(_attribute(get_attributes, session, handle, attribute)):
            names.append(name)
    return ", ".join(names)


def _certificate_details(value: bytes) -> dict:
    if not value or x509 is None:
        return {}
    try:
        certificate = x509.load_der_x509_certificate(value)
        public_key = certificate.public_key()
        if rsa is not None and isinstance(public_key, rsa.RSAPublicKey):
            key_type = f"RSA {public_key.key_size}"
        elif ec is not None and isinstance(public_key, ec.EllipticCurvePublicKey):
            key_type = f"ECDSA {public_key.key_size}"
        else:
            key_type = public_key.__class__.__name__
        return {
            "subject": certificate.subject.rfc4514_string(),
            "subject_fields": name_fields(certificate.subject),
            "issuer": certificate.issuer.rfc4514_string(),
            "issuer_fields": name_fields(certificate.issuer),
            "serial": f"{certificate.serial_number:X}",
            "key_type": key_type,
            "not_before_date": certificate.not_valid_before_utc.strftime("%d.%m.%Y %H:%M UTC"),
            "not_after_date": certificate.not_valid_after_utc.strftime("%d.%m.%Y %H:%M UTC"),
            "fingerprint": certificate.fingerprint(hashes.SHA1()).hex().upper(),
            "fingerprint_sha256": certificate.fingerprint(hashes.SHA256()).hex().upper(),
            "certificate_pem": certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        }
    except Exception:
        return {}


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


def _select_slot(table, expected_serial: str):
    get_slots = _function(table.C_GetSlotList, ctypes.c_ubyte,
                          ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong))
    get_token_info = _function(table.C_GetTokenInfo, ctypes.c_ulong,
                               ctypes.POINTER(CK_TOKEN_INFO))
    count = ctypes.c_ulong()
    if int(get_slots(1, None, ctypes.byref(count))) != CKR_OK or not count.value:
        raise RuntimeError("Токен не найден")
    slots = (ctypes.c_ulong * count.value)()
    if int(get_slots(1, slots, ctypes.byref(count))) != CKR_OK:
        raise RuntimeError("Не удалось прочитать слоты токенов")
    matches, available = [], []
    for slot in slots[:count.value]:
        info = CK_TOKEN_INFO()
        if int(get_token_info(slot, ctypes.byref(info))) != CKR_OK:
            continue
        serial = bytes(info.serialNumber).decode("ascii", errors="ignore").strip()
        available.append((slot, serial))
        if _serial_aliases(serial) & _serial_aliases(expected_serial):
            matches.append(slot)
    if len(matches) == 1:
        return matches[0]
    if len(available) == 1:
        return available[0][0]
    visible = ", ".join(serial or "без номера" for _, serial in available)
    raise RuntimeError(f"Не найден выбранный токен {expected_serial}. Доступны: {visible}")


def read_rutoken_slots() -> list[dict]:
    if platform.system() != "Windows":
        return []
    module = lib_file("rtpkcs11ecp.dll", "rtPKCS11ECP.dll")
    library = ctypes.CDLL(str(module))
    get_list = library.C_GetFunctionList
    get_list.argtypes = [ctypes.POINTER(ctypes.POINTER(CK_FUNCTION_LIST))]
    get_list.restype = ctypes.c_ulong
    functions = ctypes.POINTER(CK_FUNCTION_LIST)()
    if int(get_list(ctypes.byref(functions))) != CKR_OK or not functions:
        return []
    table = functions.contents
    initialize = _function(table.C_Initialize, ctypes.c_void_p)
    finalize = _function(table.C_Finalize, ctypes.c_void_p)
    get_slots = _function(table.C_GetSlotList, ctypes.c_ubyte,
                          ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong))
    get_slot_info = _function(table.C_GetSlotInfo, ctypes.c_ulong,
                              ctypes.POINTER(CK_SLOT_INFO))
    get_token_info = _function(table.C_GetTokenInfo, ctypes.c_ulong,
                               ctypes.POINTER(CK_TOKEN_INFO))
    initialized = int(initialize(None))
    if initialized not in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED):
        raise RuntimeError(f"Rutoken PKCS#11 init: 0x{initialized:08X}")
    initialized_here = initialized == CKR_OK
    try:
        count = ctypes.c_ulong()
        if int(get_slots(1, None, ctypes.byref(count))) != CKR_OK or not count.value:
            return []
        slots = (ctypes.c_ulong * count.value)()
        if int(get_slots(1, slots, ctypes.byref(count))) != CKR_OK:
            return []
        result = []
        for slot in slots[:count.value]:
            slot_info = CK_SLOT_INFO()
            token_info = CK_TOKEN_INFO()
            if int(get_slot_info(slot, ctypes.byref(slot_info))) != CKR_OK:
                continue
            if int(get_token_info(slot, ctypes.byref(token_info))) != CKR_OK:
                continue
            result.append({
                "reader": bytes(slot_info.slotDescription).decode(
                    "utf-8", errors="replace").strip(" \0"),
                "serial": bytes(token_info.serialNumber).decode(
                    "ascii", errors="ignore").strip(" \0"),
                "label": bytes(token_info.label).decode(
                    "utf-8", errors="replace").strip(" \0"),
                "model": bytes(token_info.model).decode(
                    "utf-8", errors="replace").strip(" \0"),
            })
        return result
    finally:
        if initialized_here:
            finalize(None)


def _read_rutoken_objects_from(module: Path) -> dict[str, list[dict]]:
    library = ctypes.CDLL(str(module))
    get_list = library.C_GetFunctionList
    get_list.argtypes = [ctypes.POINTER(ctypes.POINTER(CK_FUNCTION_LIST))]
    get_list.restype = ctypes.c_ulong
    functions = ctypes.POINTER(CK_FUNCTION_LIST)()
    if int(get_list(ctypes.byref(functions))) != CKR_OK or not functions:
        return {}
    table = functions.contents
    initialize = _function(table.C_Initialize, ctypes.c_void_p)
    finalize = _function(table.C_Finalize, ctypes.c_void_p)
    get_slots = _function(table.C_GetSlotList, ctypes.c_ubyte,
                          ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong))
    open_session = _function(table.C_OpenSession, ctypes.c_ulong, ctypes.c_ulong,
                             ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong))
    close_session = _function(table.C_CloseSession, ctypes.c_ulong)
    find_init = _function(table.C_FindObjectsInit, ctypes.c_ulong,
                          ctypes.POINTER(CK_ATTRIBUTE), ctypes.c_ulong)
    find = _function(table.C_FindObjects, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong),
                     ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong))
    find_final = _function(table.C_FindObjectsFinal, ctypes.c_ulong)
    get_attributes = _function(table.C_GetAttributeValue, ctypes.c_ulong, ctypes.c_ulong,
                               ctypes.POINTER(CK_ATTRIBUTE), ctypes.c_ulong)

    initialized = int(initialize(None))
    if initialized not in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED):
        raise RuntimeError(f"Rutoken PKCS#11 init: 0x{initialized:08X}")
    initialized_here = initialized == CKR_OK
    result = {}
    try:
        count = ctypes.c_ulong()
        if int(get_slots(1, None, ctypes.byref(count))) != CKR_OK:
            return {}
        slots = (ctypes.c_ulong * count.value)()
        if count.value and int(get_slots(1, slots, ctypes.byref(count))) != CKR_OK:
            return {}
        for slot in slots[:count.value]:
            token_info = CK_TOKEN_INFO()
            get_token_info = _function(table.C_GetTokenInfo, ctypes.c_ulong,
                                       ctypes.POINTER(CK_TOKEN_INFO))
            if int(get_token_info(slot, ctypes.byref(token_info))) != CKR_OK:
                continue
            serial = bytes(token_info.serialNumber).decode("ascii", errors="ignore").strip()
            slot_objects = []
            for alias in _serial_aliases(serial):
                result[alias] = slot_objects
            session = ctypes.c_ulong()
            if int(open_session(slot, CKF_SERIAL_SESSION, None, None, ctypes.byref(session))) != CKR_OK:
                continue
            try:
                if int(find_init(session.value, None, 0)) != CKR_OK:
                    continue
                try:
                    while True:
                        handles = (ctypes.c_ulong * 32)()
                        found = ctypes.c_ulong()
                        if int(find(session.value, handles, 32, ctypes.byref(found))) != CKR_OK or not found.value:
                            break
                        for handle in handles[:found.value]:
                            class_data = _attribute(get_attributes, session.value, handle, CKA_CLASS)
                            object_class = int.from_bytes(class_data, "little") if class_data else -1
                            label = _attribute(get_attributes, session.value, handle, CKA_LABEL)
                            object_id = _attribute(get_attributes, session.value, handle, CKA_ID)
                            object_data = {
                                "type": OBJECT_TYPES.get(object_class, f"Объект {object_class}"),
                                "class": object_class,
                                "label": label.decode("utf-8", errors="replace").strip() or "—",
                                "id": _display_id(object_id),
                                "id_hex": object_id.hex(),
                                "provider": module.name,
                                "source": "PKCS#11",
                            }
                            if object_class == 0x1:
                                object_data.update(_certificate_details(
                                    _attribute(get_attributes, session.value, handle, CKA_VALUE)))
                            elif object_class in (0x2, 0x3):
                                key_type = _ulong(_attribute(get_attributes, session.value, handle, CKA_KEY_TYPE))
                                bits = _ulong(_attribute(get_attributes, session.value, handle, CKA_MODULUS_BITS))
                                algorithm = KEY_TYPES.get(key_type, f"PKCS#11 type {key_type}" if key_type is not None else "")
                                object_data["key_type"] = f"{algorithm} {bits}" if bits else algorithm
                                object_data["usage"] = _usage(get_attributes, session.value, handle)
                            slot_objects.append(object_data)
                finally:
                    find_final(session.value)
            finally:
                close_session(session.value)
    finally:
        if initialized_here:
            finalize(None)
    return result


def read_rutoken_objects() -> dict[str, list[dict]]:
    if platform.system() != "Windows":
        return {}
    windows = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32"
    modules = (windows / "rtPKCS11.dll", windows / "rtPKCS11ECP.dll")
    merged = {}
    for module in modules:
        if not module.is_file():
            continue
        try:
            current = _read_rutoken_objects_from(module)
        except (OSError, RuntimeError):
            continue
        for serial, objects in current.items():
            destination = merged.setdefault(serial, [])
            known = {(item.get("class"), item.get("id_hex"), item.get("label"))
                     for item in destination}
            for item in objects:
                identity = (item.get("class"), item.get("id_hex"), item.get("label"))
                if identity not in known:
                    destination.append(item)
                    known.add(identity)
    return merged


def verify_user_pin(vendor: str, serial: str, pin: str) -> None:
    if platform.system() != "Windows":
        raise RuntimeError("Проверка PIN сейчас поддерживается только в Windows")
    if vendor == "Aktiv":
        module = lib_file("rtpkcs11ecp.dll", "rtPKCS11ECP.dll")
    elif vendor == "ISBC":
        system_module = lib_file("isbc_pkcs11_main.dll", "isbc_pkcs11_main.dll")
        if not system_module.is_file():
            raise RuntimeError("Не установлен системный PKCS#11-драйвер ESMART")
        module = system_module
    else:
        raise RuntimeError(f"Проверка PIN для {vendor} пока не поддерживается")

    library = ctypes.CDLL(str(module))
    get_list = library.C_GetFunctionList
    get_list.argtypes = [ctypes.POINTER(ctypes.POINTER(CK_FUNCTION_LIST))]
    get_list.restype = ctypes.c_ulong
    functions = ctypes.POINTER(CK_FUNCTION_LIST)()
    if int(get_list(ctypes.byref(functions))) != CKR_OK or not functions:
        raise RuntimeError("PKCS#11 не вернул таблицу функций")
    table = functions.contents
    initialize = _function(table.C_Initialize, ctypes.c_void_p)
    finalize = _function(table.C_Finalize, ctypes.c_void_p)
    open_session = _function(table.C_OpenSession, ctypes.c_ulong, ctypes.c_ulong,
                             ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong))
    close_session = _function(table.C_CloseSession, ctypes.c_ulong)
    login = _function(table.C_Login, ctypes.c_ulong, ctypes.c_ulong,
                      ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulong)

    initialized = int(initialize(None))
    if initialized not in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED):
        raise RuntimeError(f"PKCS#11 init: 0x{initialized:08X}")
    initialized_here = initialized == CKR_OK
    try:
        slot = _select_slot(table, serial)
        session = ctypes.c_ulong()
        opened = int(open_session(slot, CKF_SERIAL_SESSION, None, None, ctypes.byref(session)))
        if opened != CKR_OK:
            raise RuntimeError(f"Не удалось открыть токен: 0x{opened:08X}")
        try:
            encoded = pin.encode("utf-8")
            pin_buffer = (ctypes.c_ubyte * len(encoded)).from_buffer_copy(encoded)
            result = int(login(session.value, CKU_USER, pin_buffer, len(encoded)))
            ctypes.memset(pin_buffer, 0, len(encoded))
            if result not in (CKR_OK, CKR_USER_ALREADY_LOGGED_IN):
                raise RuntimeError(LOGIN_ERRORS.get(result, f"Ошибка проверки PIN: 0x{result:08X}"))
        finally:
            close_session(session.value)
    finally:
        if initialized_here:
            finalize(None)


def change_user_pin(vendor: str, serial: str, old_pin: str, new_pin: str) -> None:
    if platform.system() != "Windows":
        raise RuntimeError("Смена PIN сейчас поддерживается только в Windows")
    if vendor == "Aktiv":
        module = lib_file("rtpkcs11ecp.dll", "rtPKCS11ECP.dll")
    elif vendor == "ISBC":
        module = lib_file("isbc_pkcs11_main.dll", "isbc_pkcs11_main.dll")
        if not module.is_file():
            raise RuntimeError("Не установлен системный PKCS#11-драйвер ESMART")
    else:
        raise RuntimeError(f"Смена PIN для {vendor} пока не поддерживается")
    library = ctypes.CDLL(str(module))
    get_list = library.C_GetFunctionList
    get_list.argtypes = [ctypes.POINTER(ctypes.POINTER(CK_FUNCTION_LIST))]
    get_list.restype = ctypes.c_ulong
    functions = ctypes.POINTER(CK_FUNCTION_LIST)()
    if int(get_list(ctypes.byref(functions))) != CKR_OK or not functions:
        raise RuntimeError("PKCS#11 не вернул таблицу функций")
    table = functions.contents
    initialize = _function(table.C_Initialize, ctypes.c_void_p)
    finalize = _function(table.C_Finalize, ctypes.c_void_p)
    open_session = _function(table.C_OpenSession, ctypes.c_ulong, ctypes.c_ulong,
                             ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong))
    close_session = _function(table.C_CloseSession, ctypes.c_ulong)
    set_pin = _function(table.C_SetPIN, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ubyte),
                        ctypes.c_ulong, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulong)
    initialized = int(initialize(None))
    if initialized not in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED):
        raise RuntimeError(f"PKCS#11 init: 0x{initialized:08X}")
    initialized_here = initialized == CKR_OK
    try:
        slot = _select_slot(table, serial)
        session = ctypes.c_ulong()
        opened = int(open_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                  None, None, ctypes.byref(session)))
        if opened != CKR_OK:
            raise RuntimeError(f"Не удалось открыть токен: 0x{opened:08X}")
        try:
            old_encoded, new_encoded = old_pin.encode("utf-8"), new_pin.encode("utf-8")
            old_buffer = (ctypes.c_ubyte * len(old_encoded)).from_buffer_copy(old_encoded)
            new_buffer = (ctypes.c_ubyte * len(new_encoded)).from_buffer_copy(new_encoded)
            result = int(set_pin(session.value, old_buffer, len(old_encoded),
                                 new_buffer, len(new_encoded)))
            ctypes.memset(old_buffer, 0, len(old_encoded))
            ctypes.memset(new_buffer, 0, len(new_encoded))
            if result != CKR_OK:
                raise RuntimeError(LOGIN_ERRORS.get(result, f"Ошибка смены PIN: 0x{result:08X}"))
        finally:
            close_session(session.value)
    finally:
        if initialized_here:
            finalize(None)


def delete_object(vendor: str, serial: str, object_class: int, object_id_hex: str, pin: str) -> None:
    if platform.system() != "Windows":
        raise RuntimeError("Удаление объектов сейчас поддерживается только в Windows")
    if vendor == "Aktiv":
        module = lib_file("rtpkcs11ecp.dll", "rtPKCS11ECP.dll")
    elif vendor == "ISBC":
        module = lib_file("isbc_pkcs11_main.dll", "isbc_pkcs11_main.dll")
        if not module.is_file():
            raise RuntimeError("Не установлен системный PKCS#11-драйвер ESMART")
    else:
        raise RuntimeError(f"Удаление объектов для {vendor} пока не поддерживается")
    library = ctypes.CDLL(str(module))
    get_list = library.C_GetFunctionList
    get_list.argtypes = [ctypes.POINTER(ctypes.POINTER(CK_FUNCTION_LIST))]
    get_list.restype = ctypes.c_ulong
    functions = ctypes.POINTER(CK_FUNCTION_LIST)()
    if int(get_list(ctypes.byref(functions))) != CKR_OK or not functions:
        raise RuntimeError("PKCS#11 не вернул таблицу функций")
    table = functions.contents
    initialize = _function(table.C_Initialize, ctypes.c_void_p)
    finalize = _function(table.C_Finalize, ctypes.c_void_p)
    open_session = _function(table.C_OpenSession, ctypes.c_ulong, ctypes.c_ulong,
                             ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong))
    close_session = _function(table.C_CloseSession, ctypes.c_ulong)
    login = _function(table.C_Login, ctypes.c_ulong, ctypes.c_ulong,
                      ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulong)
    find_init = _function(table.C_FindObjectsInit, ctypes.c_ulong,
                          ctypes.POINTER(CK_ATTRIBUTE), ctypes.c_ulong)
    find = _function(table.C_FindObjects, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong),
                     ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong))
    find_final = _function(table.C_FindObjectsFinal, ctypes.c_ulong)
    destroy = _function(table.C_DestroyObject, ctypes.c_ulong, ctypes.c_ulong)
    initialized = int(initialize(None))
    if initialized not in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED):
        raise RuntimeError(f"PKCS#11 init: 0x{initialized:08X}")
    initialized_here = initialized == CKR_OK
    try:
        slot = _select_slot(table, serial)
        session = ctypes.c_ulong()
        opened = int(open_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                  None, None, ctypes.byref(session)))
        if opened != CKR_OK:
            raise RuntimeError(f"Не удалось открыть токен: 0x{opened:08X}")
        try:
            encoded = pin.encode("utf-8")
            pin_buffer = (ctypes.c_ubyte * len(encoded)).from_buffer_copy(encoded)
            logged_in = int(login(session.value, CKU_USER, pin_buffer, len(encoded)))
            ctypes.memset(pin_buffer, 0, len(encoded))
            if logged_in not in (CKR_OK, CKR_USER_ALREADY_LOGGED_IN):
                raise RuntimeError(LOGIN_ERRORS.get(logged_in, f"Ошибка проверки PIN: 0x{logged_in:08X}"))
            object_id = bytes.fromhex(object_id_hex)
            class_value = ctypes.c_ulong(object_class)
            id_buffer = (ctypes.c_ubyte * len(object_id)).from_buffer_copy(object_id)
            template = (CK_ATTRIBUTE * 2)(
                CK_ATTRIBUTE(CKA_CLASS, ctypes.cast(ctypes.byref(class_value), ctypes.c_void_p), ctypes.sizeof(class_value)),
                CK_ATTRIBUTE(CKA_ID, ctypes.cast(id_buffer, ctypes.c_void_p), len(object_id)),
            )
            if int(find_init(session.value, template, 2)) != CKR_OK:
                raise RuntimeError("Не удалось найти объект")
            try:
                handle = ctypes.c_ulong()
                found = ctypes.c_ulong()
                result = int(find(session.value, ctypes.byref(handle), 1, ctypes.byref(found)))
                if result != CKR_OK or found.value != 1:
                    raise RuntimeError("Выбранный объект не найден")
            finally:
                find_final(session.value)
            destroyed = int(destroy(session.value, handle.value))
            if destroyed != CKR_OK:
                raise RuntimeError(f"Токен отказал в удалении объекта: 0x{destroyed:08X}")
        finally:
            close_session(session.value)
    finally:
        if initialized_here:
            finalize(None)


def initialize_token(vendor: str, serial: str, label: str, so_pin: str, user_pin: str) -> None:
    if platform.system() != "Windows":
        raise RuntimeError("Инициализация токена сейчас поддерживается только в Windows")
    if vendor == "Aktiv":
        module = lib_file("rtpkcs11ecp.dll", "rtPKCS11ECP.dll")
    elif vendor == "ISBC":
        module = lib_file("isbc_pkcs11_main.dll", "isbc_pkcs11_main.dll")
        if not module.is_file():
            raise RuntimeError("Не установлен системный PKCS#11-драйвер ESMART")
    else:
        raise RuntimeError(f"Инициализация для {vendor} пока не поддерживается")
    library = ctypes.CDLL(str(module))
    get_list = library.C_GetFunctionList
    get_list.argtypes = [ctypes.POINTER(ctypes.POINTER(CK_FUNCTION_LIST))]
    get_list.restype = ctypes.c_ulong
    functions = ctypes.POINTER(CK_FUNCTION_LIST)()
    if int(get_list(ctypes.byref(functions))) != CKR_OK or not functions:
        raise RuntimeError("PKCS#11 не вернул таблицу функций")
    table = functions.contents
    initialize = _function(table.C_Initialize, ctypes.c_void_p)
    finalize = _function(table.C_Finalize, ctypes.c_void_p)
    init_token = _function(table.C_InitToken, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ubyte),
                           ctypes.c_ulong, ctypes.POINTER(ctypes.c_ubyte))
    open_session = _function(table.C_OpenSession, ctypes.c_ulong, ctypes.c_ulong,
                             ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong))
    close_session = _function(table.C_CloseSession, ctypes.c_ulong)
    login = _function(table.C_Login, ctypes.c_ulong, ctypes.c_ulong,
                      ctypes.POINTER(ctypes.c_ubyte), ctypes.c_ulong)
    init_pin = _function(table.C_InitPIN, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ubyte),
                         ctypes.c_ulong)
    initialized = int(initialize(None))
    if initialized not in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED):
        raise RuntimeError(f"PKCS#11 init: 0x{initialized:08X}")
    initialized_here = initialized == CKR_OK
    try:
        slot = _select_slot(table, serial)
        so_encoded, user_encoded = so_pin.encode("utf-8"), user_pin.encode("utf-8")
        so_buffer = (ctypes.c_ubyte * len(so_encoded)).from_buffer_copy(so_encoded)
        user_buffer = (ctypes.c_ubyte * len(user_encoded)).from_buffer_copy(user_encoded)
        label_bytes = label.encode("utf-8")[:32].ljust(32, b" ")
        label_buffer = (ctypes.c_ubyte * 32).from_buffer_copy(label_bytes)
        initialized_token = int(init_token(slot, so_buffer, len(so_encoded), label_buffer))
        if initialized_token != CKR_OK:
            ctypes.memset(so_buffer, 0, len(so_encoded))
            ctypes.memset(user_buffer, 0, len(user_encoded))
            raise RuntimeError(LOGIN_ERRORS.get(initialized_token,
                               f"Токен отказал в инициализации: 0x{initialized_token:08X}"))
        session = ctypes.c_ulong()
        opened = int(open_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                  None, None, ctypes.byref(session)))
        if opened != CKR_OK:
            ctypes.memset(so_buffer, 0, len(so_encoded))
            ctypes.memset(user_buffer, 0, len(user_encoded))
            raise RuntimeError(f"Токен очищен, но не удалось открыть его: 0x{opened:08X}")
        try:
            logged_in = int(login(session.value, CKU_SO, so_buffer, len(so_encoded)))
            if logged_in not in (CKR_OK, CKR_USER_ALREADY_LOGGED_IN):
                raise RuntimeError(f"Токен очищен, но вход SO завершился ошибкой 0x{logged_in:08X}")
            user_initialized = int(init_pin(session.value, user_buffer, len(user_encoded)))
            if user_initialized != CKR_OK:
                raise RuntimeError(f"Токен очищен, но User PIN не установлен: 0x{user_initialized:08X}")
        finally:
            ctypes.memset(so_buffer, 0, len(so_encoded))
            ctypes.memset(user_buffer, 0, len(user_encoded))
            close_session(session.value)
    finally:
        if initialized_here:
            finalize(None)
