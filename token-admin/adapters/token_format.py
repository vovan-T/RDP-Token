import platform

from adapters.tool_paths import lib_file
from adapters.vendor_cli import _run


def format_token(vendor: str, serial: str, label: str, current_admin_pin: str,
                 new_admin_pin: str, new_user_pin: str) -> None:
    if vendor != "Aktiv":
        raise RuntimeError("Безопасное форматирование этого типа токена пока не проверено")
    tool = lib_file("rtadmin.exe" if platform.system() == "Windows" else "rtadmin")
    _run(tool, "format", "-s", serial, "--auth-pin-input", "options",
         "--auth-pin", current_admin_pin, "--new-user-pin-input", "options",
         "--new-user-pin", new_user_pin, "--new-so-pin-input", "options",
         "--new-so-pin", new_admin_pin, "--label", label, "--no-pin-file", timeout=300)
