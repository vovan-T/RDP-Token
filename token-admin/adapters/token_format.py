from adapters.vendor_cli import _application_root, _run


def format_token(vendor: str, serial: str, label: str, current_admin_pin: str,
                 new_admin_pin: str, new_user_pin: str) -> None:
    if vendor != "Aktiv":
        raise RuntimeError("Безопасное форматирование этого типа токена пока не проверено")
    tool = _application_root() / "vendor" / "rutoken" / "tools" / "windows-x64" / "rtadmin.exe"
    _run(tool, "format", "-s", serial, "--auth-pin-input", "options",
         "--auth-pin", current_admin_pin, "--new-user-pin-input", "options",
         "--new-user-pin", new_user_pin, "--new-so-pin-input", "options",
         "--new-so-pin", new_admin_pin, "--label", label, "--no-pin-file", timeout=300)
