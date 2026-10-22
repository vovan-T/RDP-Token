import platform
import string

from adapters.tool_paths import lib_file
from adapters.vendor_cli import _run


def normalize_rtadmin_serial(value: str) -> str:
    serial = str(value or "").strip()
    hexadecimal = serial.startswith("{") and serial.endswith("}")
    if serial.startswith("{") and serial.endswith("}"):
        serial = serial[1:-1].strip()
    serial = "".join(serial.split())
    if serial.lower().startswith("0x"):
        hexadecimal = True
        serial = serial[2:]
    if not serial or any(char not in string.hexdigits for char in serial):
        raise RuntimeError("Некорректный серийный номер Rutoken")
    if hexadecimal or any(char in "abcdefABCDEF" for char in serial):
        return str(int(serial, 16))
    return serial


def format_token(vendor: str, serial: str, label: str, current_admin_pin: str,
                 new_admin_pin: str, new_user_pin: str) -> None:
    if vendor != "Aktiv":
        raise RuntimeError("Безопасное форматирование этого типа токена пока не проверено")
    tool = lib_file("rtadmin.exe" if platform.system() == "Windows" else "rtadmin")
    _run(tool, "format", "-s", normalize_rtadmin_serial(serial), "--auth-pin-input", "options",
         "--auth-pin", current_admin_pin, "--new-user-pin-input", "options",
         "--new-user-pin", new_user_pin, "--new-so-pin-input", "options",
         "--new-so-pin", new_admin_pin, "--label", label, "--no-pin-file", timeout=300)
