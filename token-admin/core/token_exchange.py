"""Public registration cards. Never export PINs, private keys or access grants."""
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

FORMAT = "rdp-token-registration"
MAX_BYTES = 256 * 1024


def normalize_serial(value):
    if not isinstance(value, str):
        raise ValueError("Серийный номер сертификата должен быть строкой HEX.")
    text = value.replace(":", "").replace(" ", "").upper()
    if not re.fullmatch(r"[0-9A-F]{1,128}", text) or int(text, 16) == 0:
        raise ValueError("Некорректный серийный номер сертификата (HEX).")
    return text.lstrip("0")


def _text(value, title, required=True):
    if not isinstance(value, str) or len(value) > 4096:
        raise ValueError(f"Некорректное поле «{title}».")
    value = value.strip()
    if required and not value:
        raise ValueError(f"Не заполнено поле «{title}».")
    if any(ord(char) < 32 for char in value):
        raise ValueError(f"Управляющие символы в поле «{title}».")
    return value


def _certificate_record(raw):
    if b"PRIVATE KEY" in raw or b"CERTIFICATE REQUEST" in raw:
        raise ValueError("Нужен публичный сертификат, не закрытый ключ и не CSR.")
    try:
        if b"-----BEGIN" in raw:
            if raw.count(b"-----BEGIN CERTIFICATE-----") != 1:
                raise ValueError("Выбери один клиентский сертификат, без цепочки CA.")
            cert = x509.load_pem_x509_certificate(raw)
        else:
            cert = x509.load_der_x509_certificate(raw)
    except ValueError as exc:
        raise ValueError("Не удалось прочитать один сертификат PEM/DER. P12/PFX и CSR не подходят.") from exc
    try:
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("Это сертификат CA. Нужен клиентский сертификат владельца токена.")
    except x509.ExtensionNotFound:
        pass
    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return {
        "label": names[0].value if names else "Новый токен",
        "serial": f"{cert.serial_number:X}",
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex().upper(),
        "not_before_date": cert.not_valid_before_utc.strftime("%d.%m.%Y %H:%M UTC"),
        "not_after_date": cert.not_valid_after_utc.strftime("%d.%m.%Y %H:%M UTC"),
        "certificate_pem": cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        "certificate_present": True,
        "date_warning": not (cert.not_valid_before_utc <= datetime.now(timezone.utc) <= cert.not_valid_after_utc),
    }


def registration_record(source, label=None):
    if not isinstance(source, dict):
        raise ValueError("Карточка токена должна быть объектом JSON.")
    serial = normalize_serial(source.get("serial"))
    pem = source.get("certificate_pem")
    if pem:
        if not isinstance(pem, str) or len(pem) > MAX_BYTES:
            raise ValueError("Некорректное поле сертификата.")
        record = _certificate_record(pem.encode("utf-8"))
        if normalize_serial(record["serial"]) != serial:
            raise ValueError("Серийный номер карточки не совпадает с сертификатом.")
        supplied = source.get("fingerprint_sha256", "").replace(":", "").upper()
        if supplied and supplied != record["fingerprint_sha256"]:
            raise ValueError("Отпечаток карточки не совпадает с сертификатом.")
    else:
        record = {
            "serial": serial,
            "subject": _text(source.get("subject"), "Subject"),
            "issuer": _text(source.get("issuer"), "Issuer"),
            "certificate_present": False,
            "date_warning": False,
        }
        fingerprint = source.get("fingerprint_sha256", "")
        if not isinstance(fingerprint, str):
            raise ValueError("Некорректный отпечаток SHA-256.")
        fingerprint = fingerprint.replace(":", "").upper()
        if fingerprint:
            if not re.fullmatch(r"[0-9A-F]{64}", fingerprint):
                raise ValueError("Некорректный отпечаток SHA-256.")
            record["fingerprint_sha256"] = fingerprint
    record["label"] = _text(label if label is not None else source.get("label", record.get("label", "Новый токен")), "Название")
    return record


def export_bytes(source, label=None):
    record = registration_record(source, label)
    # Explicit whitelist: never copy provider/container state, PINs, roles or grants.
    fields = ("label", "serial", "subject", "issuer", "fingerprint_sha256", "certificate_pem")
    payload = {"format": FORMAT, "version": 1,
               "token": {name: record[name] for name in fields if name in record}}
    return (json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def import_bytes(raw):
    if not raw or len(raw) > MAX_BYTES:
        raise ValueError("Файл пустой или больше 256 КБ.")
    text = None
    try:
        text = raw.decode("utf-8-sig").strip()
    except UnicodeDecodeError:
        pass
    if text and text.startswith(("{", "[")):
        try:
            payload = json.loads(text)
        except (ValueError, RecursionError) as exc:
            raise ValueError("Некорректный JSON карточки токена.") from exc
        if not isinstance(payload, dict) or payload.get("format") != FORMAT or type(payload.get("version")) is not int or payload["version"] != 1:
            raise ValueError("Неизвестный формат или версия карточки токена.")
        return registration_record(payload.get("token"))
    return _certificate_record(raw)


def load_file(path):
    with Path(path).open("rb") as handle:
        return import_bytes(handle.read(MAX_BYTES + 1))


def suggested_filename(record):
    label = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", record.get("label", "token")).strip(" .")[:80]
    return f"token-{label or 'certificate'}-{normalize_serial(record['serial'])[-12:]}.rdptoken.json"
