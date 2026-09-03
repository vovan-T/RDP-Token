import json
import os
import base64
import textwrap
import secrets
from datetime import datetime
from pathlib import Path

from adapters.vendor_cli import _application_root, _run, read_esmart_details


def _safe(value: str) -> str:
    return value.replace("\r", " ").replace("\n", " ").strip()


def _slot_for(serial: str) -> str:
    wanted = "".join(char for char in serial.upper() if char.isalnum())
    for token in read_esmart_details():
        candidate = "".join(char for char in token.get("serial", "").upper() if char.isalnum())
        if candidate == wanted:
            return str(token["slot_id"])
    raise RuntimeError(f"ESMART с серийным номером {serial} не найден")


def _tool() -> Path:
    return _application_root() / "vendor" / "esmart" / "tools" / "windows-x64" / "PKIClientCli.exe"


def _check_json(output: str, operation: str) -> dict:
    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{operation}: ESMART вернул некорректный ответ") from exc
    if not payload.get("success"):
        detail = payload.get("error") or payload.get("message") or payload
        raise RuntimeError(f"{operation}: {detail}")
    return payload


def _normalize_csr_to_pem(path: Path) -> None:
    data = path.read_bytes()
    if data.lstrip().startswith(b"-----BEGIN CERTIFICATE REQUEST-----"):
        return
    encoded = base64.b64encode(data).decode("ascii")
    pem = "-----BEGIN CERTIFICATE REQUEST-----\n"
    pem += "\n".join(textwrap.wrap(encoded, 64))
    pem += "\n-----END CERTIFICATE REQUEST-----\n"
    path.write_text(pem, encoding="ascii")


def create_esmart_request(serial: str, key_label: str, common_name: str, upn: str,
                          key_type: str, pin: str, request_path: Path | None = None,
                          subject_fields: dict[str, str] | None = None) -> Path:
    if key_type not in ("ECDSA:256", "RSA:1024", "RSA:2048", "RSA:3072", "RSA:4096"):
        raise ValueError(f"Неподдерживаемый алгоритм: {key_type}")
    slot_id = _slot_for(serial)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    directory = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "RDP-Token" / "work" / serial
    directory.mkdir(parents=True, exist_ok=True)
    base_name = "".join(char if char.isalnum() or char in "-_" else "-" for char in common_name)
    request_path = request_path or directory / f"{base_name}-{stamp}.req"
    request_path.parent.mkdir(parents=True, exist_ok=True)
    template_path = directory / f"{base_name}-{stamp}.tmpl"
    metadata_path = directory / f"{base_name}-{stamp}.json"
    object_id = secrets.token_hex(16).upper()
    cli_key_type = "ECDSA" if key_type == "ECDSA:256" else key_type
    subject_fields = dict(subject_fields or {})
    subject_fields["CN"] = common_name
    subject_oids = (("CN", "2.5.4.3"), ("O", "2.5.4.10"),
                    ("OU", "2.5.4.11"), ("C", "2.5.4.6"),
                    ("serialNumber", "2.5.4.5"))
    template = ["[DN]"]
    template.extend(f"{oid}={_safe(subject_fields.get(name, ''))}"
                    for name, oid in subject_oids if subject_fields.get(name, "").strip())
    template.extend([
        "[ATTRIBUTES]",
        "[EXTENSIONS]",
        "keyUsage=digitalSignature,keyEncipherment=TRUE",
        "extKeyUsage=clientAuth,smartCardLogon=FALSE",
    ])
    if upn:
        template.append(f"1.3.6.1.4.1.311.20.2.3={_safe(upn)}=FALSE")
    template_path.write_text("\n".join(template) + "\n", encoding="utf-8")
    label = _safe(key_label or common_name)[:64]
    generated = _run(_tool(), "genkey", "--slotid", slot_id, "--pin", pin,
                     "--keytype", cli_key_type, "--id", object_id, "--label", label,
                     "--outform", "json", timeout=300)
    _check_json(generated, "Генерация ключа")
    metadata_path.write_text(json.dumps({
        "serial": serial, "slot_id": slot_id, "object_id": object_id,
        "label": label, "key_type": key_type, "common_name": common_name,
        "upn": upn, "subject_fields": subject_fields, "request": str(request_path),
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        created = _run(_tool(), "csr", "--slotid", slot_id, "--pin", pin,
                       "--path", str(template_path), "--csrpath", str(request_path),
                       "--pubkeyid", object_id, "--privkeyid", object_id,
                       "--outform", "json", timeout=300)
        _check_json(created, "Создание CSR")
    except Exception as exc:
        raise RuntimeError(
            f"Ключ уже создан на ESMART (ID {object_id}), но CSR создать не удалось: {exc}"
        ) from exc
    if not request_path.is_file():
        raise RuntimeError(f"ESMART сообщил об успехе, но файл CSR не найден: {request_path}")
    _normalize_csr_to_pem(request_path)
    return request_path


def install_esmart_certificate(serial: str, certificate_path: Path, pin: str) -> None:
    if not certificate_path.is_file():
        raise RuntimeError("Файл сертификата не найден")
    slot_id = _slot_for(serial)
    output = _run(_tool(), "importcert", "--slotid", slot_id, "--pin", pin,
                  "--path", str(certificate_path), "--outform", "json", timeout=300)
    _check_json(output, "Установка сертификата")
