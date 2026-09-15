import time

from adapters.pcsc import scan_tokens
from adapters.pkcs11_inventory import read_provider_objects, read_provider_slots
from adapters.provider_registry import providers_for
from adapters.vendor_cli import read_esmart_details, read_rutoken_details
from adapters.windows_cert_inventory import read_windows_rutoken_objects
from core.diagnostics import logger


LOG = logger()


def _result_size(value):
    if isinstance(value, dict):
        return f"groups={len(value)} objects={sum(len(item) for item in value.values())}"
    try:
        return f"items={len(value)}"
    except TypeError:
        return f"type={type(value).__name__}"


def _read_safely(stage, reader):
    started = time.monotonic()
    LOG.info("Inventory stage start: %s", stage)
    try:
        value = reader()
        LOG.info(
            "Inventory stage done: %s duration=%.2fs %s",
            stage, time.monotonic() - started, _result_size(value),
        )
        return value, ""
    except Exception as exc:
        LOG.exception(
            "Inventory stage failed: %s duration=%.2fs error=%s",
            stage, time.monotonic() - started, exc,
        )
        return [], str(exc)


def _merge(token, details):
    for name in ("label", "serial", "model", "memory", "user_pin_attempts",
                 "admin_pin_attempts", "slot_id", "key_options"):
        value = details.get(name)
        if value not in (None, ""):
            setattr(token, name, value)


def _merge_objects(existing, incoming):
    known = {
        (item.get("class", item.get("type")), item.get("id_hex", item.get("id")),
         item.get("fingerprint", ""), item.get("label", ""))
        for item in existing
    }
    for item in incoming or ():
        identity = (
            item.get("class", item.get("type")), item.get("id_hex", item.get("id")),
            item.get("fingerprint", ""), item.get("label", ""),
        )
        if identity not in known:
            existing.append(item)
            known.add(identity)


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


def _matching_slot(token, slots):
    reader = token.reader.casefold().strip()
    exact = [item for item in slots if str(item.get("reader", "")).casefold().strip() == reader]
    if len(exact) == 1:
        return exact[0]
    contained = [item for item in slots if reader and (
        reader in str(item.get("reader", "")).casefold()
        or str(item.get("reader", "")).casefold() in reader
    )]
    if len(contained) == 1:
        return contained[0]
    if token.serial:
        serial = [item for item in slots if
                  _serial_aliases(item.get("serial", "")) & _serial_aliases(token.serial)]
        if len(serial) == 1:
            return serial[0]
    return slots[0] if len(slots) == 1 else None


def scan_inventory():
    started = time.monotonic()
    LOG.info("Inventory scan start")
    tokens, pcsc_error = _read_safely("PC/SC readers", scan_tokens)
    rutokens, rutoken_error = _read_safely("Rutoken control utility", read_rutoken_details)
    windows_objects, windows_objects_error = _read_safely("Windows CSP/KSP certificates", read_windows_rutoken_objects)
    esmarts, esmart_error = _read_safely("ESMART PKCS#11", read_esmart_details)
    provider_cache = {}
    provider_errors = []
    for token in (item for item in tokens if item.state == "READY"):
        if token.vendor == "Aktiv":
            details = next((item for item in rutokens if
                            not token.serial or _serial_aliases(item.get("serial", ""))
                            & _serial_aliases(token.serial)), None)
            if details:
                _merge(token, details)
        elif token.vendor == "ISBC":
            details = next((item for item in esmarts if item.get("reader") == token.reader), None)
            if details:
                _merge(token, details)
                _merge_objects(token.objects, details.get("objects", []))

        for spec, module in providers_for(token.vendor, token.reader, token.model):
            cache_key = str(module.resolve())
            if cache_key not in provider_cache:
                try:
                    provider_cache[cache_key] = (
                        read_provider_slots(module), read_provider_objects(module), "",
                    )
                except (OSError, RuntimeError) as exc:
                    LOG.exception("Provider failed: id=%s module=%s error=%s",
                                  spec.provider_id, module, exc)
                    provider_cache[cache_key] = ([], {}, str(exc))
            slots, objects, error = provider_cache[cache_key]
            if error:
                provider_errors.append(f"{spec.name}: {error}")
                continue
            slot = _matching_slot(token, slots)
            if slot is None:
                continue
            _merge(token, slot)
            token.provider_id = spec.provider_id
            token.provider_name = spec.name
            token.provider_path = str(module)
            aliases = _serial_aliases(token.serial) if token.serial else set()
            selected_objects = next((objects[item] for item in aliases if item in objects), [])
            _merge_objects(token.objects, selected_objects)
            LOG.info(
                "Provider selected: reader=%r provider=%s module=%s serial_suffix=%s objects=%d",
                token.reader, spec.provider_id, module.name, str(token.serial)[-4:],
                len(selected_objects),
            )
            break

        token_windows_objects = []
        if isinstance(windows_objects, dict):
            aliases = _serial_aliases(token.serial) if token.serial else set()
            token_windows_objects = next(
                (windows_objects[item] for item in aliases if item in windows_objects), [])
            if not token_windows_objects:
                token_windows_objects = windows_objects.get(f"reader:{token.reader}", [])
        _merge_windows_objects(token.objects, token_windows_objects)
        _enrich_pkcs11_context(token.objects)
    warnings = []
    if pcsc_error:
        warnings.append(f"PC/SC: {pcsc_error}")
    if rutoken_error:
        warnings.append(f"Rutoken: {rutoken_error}")
    if windows_objects_error:
        warnings.append(f"Windows CSP/KSP: {windows_objects_error}")
    if esmart_error:
        warnings.append(f"ESMART: {esmart_error}")
    warnings.extend(dict.fromkeys(provider_errors))
    LOG.info(
        "Inventory scan done duration=%.2fs readers=%d ready=%d warnings=%d",
        time.monotonic() - started, len(tokens),
        sum(token.state == "READY" for token in tokens), len(warnings),
    )
    return tokens, warnings
