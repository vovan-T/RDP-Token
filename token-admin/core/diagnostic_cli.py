import argparse
import ctypes
import json
import os
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

from adapters.pkcs11_inventory import verify_user_pin
from core.diagnostics import log_path, logger
from core.inventory import scan_inventory
from core.version import APP_NAME, APP_VERSION


LOG = logger()
OBJECT_FIELDS = (
    "type", "class", "label", "id", "id_hex", "key_type", "usage",
    "subject", "issuer", "serial", "not_before_date", "not_after_date",
    "fingerprint", "fingerprint_sha256", "source", "provider", "container",
    "unique_container",
)


def _attach_parent_console():
    if os.name != "nt" or sys.stdout is not None:
        return
    if not ctypes.windll.kernel32.AttachConsole(ctypes.c_ulong(-1).value):
        return
    sys.stdin = open("CONIN$", "r", encoding="utf-8", errors="replace")
    sys.stdout = open("CONOUT$", "w", encoding="utf-8", errors="replace")
    sys.stderr = open("CONOUT$", "w", encoding="utf-8", errors="replace")


def _report_path(value: str | None) -> Path:
    if value:
        return Path(value).expanduser().resolve()
    base = (os.getenv("LOCALAPPDATA") or os.getenv("APPDATA")) if os.name == "nt" else None
    directory = Path(base) / "RDP-Token" / "reports" if base else \
        Path.home() / ".rdp-token" / "reports"
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return directory / f"token-diagnostics-{stamp}.json"


def _safe_value(value):
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_safe_value(item) for item in value]
    return str(value)


def _safe_object(value: dict) -> dict:
    return {
        name: _safe_value(value[name])
        for name in OBJECT_FIELDS
        if name in value and value[name] not in (None, "", [], {})
    }


def _token_record(token) -> dict:
    return {
        "reader": token.reader,
        "atr": token.atr,
        "vendor": token.vendor,
        "model": token.model,
        "state": token.state,
        "error": token.error,
        "label": token.label,
        "serial": token.serial,
        "user_pin_attempts": token.user_pin_attempts,
        "admin_pin_attempts": token.admin_pin_attempts,
        "memory": token.memory,
        "slot_id": token.slot_id,
        "key_options": list(token.key_options),
        "objects": [_safe_object(item) for item in token.objects],
        "pin_test": "not_requested",
    }


class _PinDialogs:
    def __init__(self):
        import tkinter as tk

        self._tk = tk
        self.root = tk.Tk()
        self.root.withdraw()
        self.root.attributes("-topmost", True)

    def ask(self, token_name: str):
        from tkinter import simpledialog

        return simpledialog.askstring(
            "Проверка PIN",
            f"{token_name}\n\nБудет выполнена одна попытка входа.\nВведи пользовательский PIN:",
            show="*", parent=self.root,
        )

    def close(self):
        self.root.destroy()


def _show_result(message: str, failed: bool):
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        function = messagebox.showwarning if failed else messagebox.showinfo
        function("Диагностика токенов", message, parent=root)
        root.destroy()
    except Exception:
        pass


def _run_pin_tests(tokens, records) -> bool:
    dialogs = _PinDialogs()
    failed = False
    try:
        for token, record in zip(tokens, records):
            if token.state != "READY":
                record["pin_test"] = "not_ready"
                continue
            if token.vendor not in ("Aktiv", "ISBC"):
                record["pin_test"] = "unsupported"
                continue
            name = token.label or token.model or token.reader
            pin = dialogs.ask(name)
            if pin is None:
                record["pin_test"] = "cancelled"
                continue
            if not pin:
                record["pin_test"] = "empty_pin_refused"
                failed = True
                continue
            try:
                verify_user_pin(token.vendor, token.serial, pin)
            except Exception as exc:
                record["pin_test"] = "failed"
                record["pin_error"] = str(exc)
                failed = True
                LOG.warning("Command diagnostic PIN test failed: reader=%r error=%s", token.reader, exc)
            else:
                record["pin_test"] = "ok"
                LOG.info("Command diagnostic PIN test passed: reader=%r", token.reader)
            finally:
                pin = None
    finally:
        dialogs.close()
    return failed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="RDP-Token token diagnostics")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--diagnose", action="store_true", help="read tokens without PIN")
    mode.add_argument("--test-tokens", action="store_true", help="read tokens and test PIN once")
    mode.add_argument("--version", action="store_true", help="print application version")
    parser.add_argument("--report", metavar="FILE", help="diagnostic JSON destination")
    parser.add_argument("--quiet", action="store_true", help="do not show the final dialog")
    return parser


def main(arguments=None) -> int:
    _attach_parent_console()
    args = _parser().parse_args(arguments)
    if args.version:
        if sys.stdout is not None:
            print(f"{APP_NAME} {APP_VERSION}")
        return 0

    report_path = _report_path(args.report)
    LOG.info("Command diagnostic start mode=%s", "pin-test" if args.test_tokens else "inventory")
    tokens, warnings = scan_inventory()
    records = [_token_record(token) for token in tokens]
    failed = _run_pin_tests(tokens, records) if args.test_tokens else False
    payload = {
        "schema": "rdp-token-diagnostics/v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "application": {"name": APP_NAME, "version": APP_VERSION},
        "host": {"os": platform.system(), "release": platform.release(), "python": platform.python_version()},
        "log_file": str(log_path()),
        "warnings": warnings,
        "tokens": records,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    ready = sum(token.state == "READY" for token in tokens)
    message = f"Обнаружено токенов: {ready}\nОтчёт: {report_path}"
    if sys.stdout is not None:
        print(message)
    LOG.info("Command diagnostic done tokens=%d failed=%s report=%s", ready, failed, report_path)
    if not args.quiet:
        _show_result(message, failed)
    return 1 if failed else 0
