from adapters.pcsc import scan_tokens
from adapters.pkcs11_inventory import read_rutoken_objects, read_rutoken_slots
from adapters.vendor_cli import read_esmart_details, read_rutoken_details
from adapters.windows_cert_inventory import read_windows_rutoken_objects


def _read_safely(reader):
    try:
        return reader(), ""
    except Exception as exc:
        return [], str(exc)


def _merge(token, details):
    for name in ("label", "serial", "model", "memory", "user_pin_attempts",
                 "admin_pin_attempts", "slot_id", "key_options", "objects"):
        value = details.get(name)
        if value not in (None, ""):
            setattr(token, name, value)


def _serial_aliases(value):
    normalized = "".join(char for char in str(value).upper() if char.isalnum()).lstrip("0") or "0"
    aliases = {normalized}
    try:
        if normalized.isdigit():
            aliases.add(f"{int(normalized):X}")
        elif all(char in "0123456789ABCDEF" for char in normalized):
            aliases.add(str(int(normalized, 16)))
    except ValueError:
        pass
    return aliases


def _merge_windows_objects(existing, windows_objects):
    existing_fingerprints = {item.get("fingerprint") for item in existing if item.get("fingerprint")}
    for item in windows_objects:
        fingerprint = item.get("fingerprint")
        if fingerprint in existing_fingerprints:
            if "сертификат" in str(item.get("type", "")).lower():
                match = next((candidate for candidate in existing
                              if candidate.get("fingerprint") == fingerprint), None)
                if match:
                    for field in ("provider", "container", "unique_container", "source"):
                        if item.get(field):
                            match[field] = item[field]
            continue
        existing.append(item)
        if fingerprint and "сертификат" in str(item.get("type", "")).lower():
            existing_fingerprints.add(fingerprint)


def _enrich_pkcs11_context(objects):
    """Attach the matching key context to certificate objects with the same CKA_ID."""
    groups = {}
    for item in objects:
        object_id = item.get("id_hex")
        if object_id:
            groups.setdefault(object_id, []).append(item)
    for object_id, members in groups.items():
        key = next((item for item in members
                    if "закрытый ключ" in str(item.get("type", "")).lower()), None)
        if key is None:
            key = next((item for item in members
                        if "открытый ключ" in str(item.get("type", "")).lower()), None)
        key_label = (key or {}).get("label") or "Ключ без названия"
        container = f"{key_label} [CKA_ID {object_id.upper()}]"
        provider = next((item.get("provider") for item in members if item.get("provider")), "")
        for item in members:
            item.setdefault("provider", provider)
            item.setdefault("container", container)
            item.setdefault("source", "PKCS#11")


def scan_inventory():
    tokens = scan_tokens()
    rutokens, rutoken_error = _read_safely(read_rutoken_details)
    rutoken_slots, rutoken_slots_error = _read_safely(read_rutoken_slots)
    rutoken_objects, rutoken_objects_error = _read_safely(read_rutoken_objects)
    windows_objects, windows_objects_error = _read_safely(read_windows_rutoken_objects)
    esmarts, esmart_error = _read_safely(read_esmart_details)
    for token in (item for item in tokens if item.state == "READY" and item.vendor == "Aktiv"):
        slot = next((item for item in rutoken_slots if item.get("reader") == token.reader), None)
        if not slot:
            continue
        _merge(token, slot)
        details = next((item for item in rutokens
                        if _serial_aliases(item.get("serial", "")) & _serial_aliases(token.serial)), None)
        if details:
            _merge(token, details)
        key = "".join(char for char in token.serial.upper() if char.isalnum()).lstrip("0") or "0"
        aliases = {key}
        if key.isdigit():
            aliases.add(f"{int(key):X}")
        token.objects = next((rutoken_objects[item] for item in aliases if item in rutoken_objects), []) \
            if isinstance(rutoken_objects, dict) else []
        token_windows_objects = next((windows_objects[item] for item in aliases if item in windows_objects), []) \
            if isinstance(windows_objects, dict) else []
        _merge_windows_objects(token.objects, token_windows_objects)
        _enrich_pkcs11_context(token.objects)
    for token in (item for item in tokens if item.state == "READY" and item.vendor == "ISBC"):
        details = next((item for item in esmarts if item.get("reader") == token.reader), None)
        if details:
            _merge(token, details)
    warnings = []
    if rutoken_error:
        warnings.append(f"Rutoken: {rutoken_error}")
    if rutoken_slots_error:
        warnings.append(f"Слоты Rutoken: {rutoken_slots_error}")
    if rutoken_objects_error:
        warnings.append(f"Объекты Rutoken: {rutoken_objects_error}")
    if windows_objects_error:
        warnings.append(f"Windows CSP/KSP: {windows_objects_error}")
    if esmart_error:
        warnings.append(f"ESMART: {esmart_error}")
    return tokens, warnings
