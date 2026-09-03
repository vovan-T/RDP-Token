import json
import platform
import re
import subprocess
import sys
from pathlib import Path


def _application_root() -> Path:
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))


def _run(executable: Path, *arguments: str, timeout: int = 15) -> str:
    if platform.system() != "Windows":
        return ""
    if not executable.is_file():
        raise RuntimeError(f"Не найдена штатная утилита: {executable.name}")
    result = subprocess.run(
        [str(executable), *arguments], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), timeout=timeout,
    )
    output = result.stdout.decode("utf-8", errors="replace")
    if "�" in output:
        output = result.stdout.decode("cp1251", errors="replace")
    if result.returncode != 0:
        raise RuntimeError(output.strip() or f"{executable.name}: код {result.returncode}")
    return output


def _value(text: str, name: str) -> str:
    match = re.search(rf"^\s*{re.escape(name)}\s*:\s*(.*?)\s*$", text, re.MULTILINE)
    return match.group(1).strip() if match else ""


def read_rutoken_details() -> list[dict]:
    tool = _application_root() / "vendor" / "rutoken" / "tools" / "windows-x64" / "rtadmin.exe"
    serials = re.findall(r"-\s*(\d+)\s*$", _run(tool, "list-tokens"), re.MULTILINE)
    result = []
    for serial in serials:
        text = _run(tool, "info", "-s", serial)
        result.append({
            "label": _value(text, "Label"), "serial": _value(text, "Serial number") or serial,
            "model": _value(text, "Model"), "memory": _value(text, "Memory(KB) (free/all)"),
            "user_pin_attempts": _value(text, "User's PIN retry count (left/all)"),
            "admin_pin_attempts": _value(text, "Admin's PIN retry count (left/all)"),
        })
    return result


def set_rutoken_label(serial: str, pin: str, label: str) -> None:
    tool = _application_root() / "vendor" / "rutoken" / "tools" / "windows-x64" / "rtadmin.exe"
    _run(
        tool, "set-label", "-s", serial,
        "--auth-pin-input", "options", "--auth-pin", pin,
        "--label", label, "--no-pin-file", "--no-log",
    )


def read_esmart_details() -> list[dict]:
    tool = _application_root() / "vendor" / "esmart" / "tools" / "windows-x64" / "PKIClientCli.exe"
    blocks = re.split(r"(?=^Slot\s+\d+:)", _run(tool, "listslots"), flags=re.MULTILINE)
    result = []
    for block in blocks:
        slot = re.search(r"^Slot\s+(\d+):\s*(.*?)\s*\(", block, re.MULTILINE)
        if not slot:
            continue
        slot_id, reader = slot.groups()
        item = {
            "reader": reader.strip(), "slot_id": slot_id, "label": _value(block, "token label"),
            "serial": _value(block, "serial num"), "model": _value(block, "token model"),
            "user_pin_attempts": _value(block, "PIN attempts") or "—",
            "admin_pin_attempts": _value(block, "SOPIN attempts") or "—", "objects": [],
        }
        try:
            payload = json.loads(_run(tool, "list", "--slotid", slot_id, "--outform", "json", "--verbose", "1"))
            if payload.get("success"):
                item["objects"] = payload.get("return", {}).get("objects", [])
                for token_object in item["objects"]:
                    if token_object.get("type") == "certificate":
                        token_object["subject"] = (
                            token_object.get("subject") or token_object.get("subject_cn", "")
                        )
                        token_object["issuer"] = (
                            token_object.get("issuer") or token_object.get("issuer_cn", "")
                        )
        except (RuntimeError, json.JSONDecodeError):
            pass
        try:
            payload = json.loads(_run(tool, "listm", "--slotid", slot_id, "--outform", "json"))
            mechanisms = payload.get("return", {}).get("mechanisms", []) if payload.get("success") else []
            options = []
            for mechanism in mechanisms:
                if mechanism.get("name") == "ECDSA_KEY_PAIR_GEN":
                    options.append(f"ECDSA:{mechanism.get('keySizeMax', 256)}")
                elif mechanism.get("name") == "RSA_PKCS_KEY_PAIR_GEN":
                    minimum = int(mechanism.get("keySizeMin", 0))
                    maximum = int(mechanism.get("keySizeMax", 0))
                    for size in (2048, 3072, 4096, 1024):
                        if minimum <= size <= maximum and f"RSA:{size}" not in options:
                            options.append(f"RSA:{size}")
            item["key_options"] = sorted(options, key=lambda value: (not value.startswith("ECDSA:"), value))
        except (RuntimeError, json.JSONDecodeError, TypeError, ValueError):
            item["key_options"] = []
        result.append(item)
    return result
