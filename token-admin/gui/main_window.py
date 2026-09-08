import json
import platform
import tempfile
import tkinter as tk
import webbrowser
import zipfile
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from cryptography import x509
from cryptography.x509.oid import NameOID

from core.inventory import scan_inventory
from adapters.pkcs11_inventory import change_user_pin, delete_object, initialize_token, verify_user_pin
from adapters.esmart_requests import create_esmart_request, install_esmart_certificate
from adapters.rutoken_requests import (
    create_rutoken_request, install_rutoken_certificate,
    rutoken_rsa_key_sizes, supports_rutoken_sdk,
)
from adapters.token_format import format_token
from adapters.vendor_cli import set_rutoken_label
from adapters.windows_certreq import create_smartcard_request, install_smartcard_certificate
from core.settings import ClientSettings, load_settings, save_settings
from core.version import APP_BRAND, APP_NAME, APP_VERSION, SUPPORTED_TOKENS
from gui.icons import CenteredToplevel, ToolTip, action_button, icon_button, load_icons, resource_root
from gui.management_tab import ManagementFrame
from gui.token_exchange_dialogs import export_card


class SettingsDialog(CenteredToplevel):
    def __init__(self, parent, settings, on_save):
        super().__init__(parent)
        self.title("Настройки сервера")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.on_save = on_save
        body = ttk.Frame(self, padding=18)
        body.pack(fill="both", expand=True)
        self.address = tk.StringVar(value=settings.server_address)
        self.port = tk.StringVar(value=str(settings.server_port))
        self.tls_name = tk.StringVar(value=settings.tls_server_name)
        for row, (label, variable) in enumerate((
            ("Адрес сервера (IP или DNS)", self.address),
            ("HTTPS-порт", self.port),
            ("Имя сервера для проверки TLS", self.tls_name),
        )):
            ttk.Label(body, text=label).grid(row=row * 2, column=0, sticky="w", pady=(0, 5))
            ttk.Entry(body, textvariable=variable, width=44).grid(row=row * 2 + 1, column=0, sticky="ew", pady=(0, 12))
        ttk.Label(body, text="Если указан DNS-адрес, имя TLS обычно совпадает с ним.",
                  style="Muted.TLabel").grid(row=6, column=0, sticky="w")
        buttons = ttk.Frame(body)
        buttons.grid(row=7, column=0, sticky="e", pady=(16, 0))
        action_button(buttons, "Отмена", self.destroy).pack(side="left", padx=(0, 7))
        action_button(buttons, "Сохранить", self._save).pack(side="left")
        self.bind("<Escape>", lambda _event: self.destroy())
        self.bind("<Return>", lambda _event: self._save())
        self.wait_visibility()
        self.focus_force()

    def _save(self):
        address = self.address.get().strip()
        tls_name = self.tls_name.get().strip()
        try:
            port = int(self.port.get())
        except ValueError:
            port = 0
        if not address:
            messagebox.showerror("Настройки", "Укажи IP или DNS-адрес сервера.", parent=self)
            return
        if not 1 <= port <= 65535:
            messagebox.showerror("Настройки", "Порт должен быть от 1 до 65535.", parent=self)
            return
        if not tls_name:
            tls_name = address
        self.on_save(ClientSettings(address, port, tls_name))
        self.destroy()


class PinDialog(CenteredToplevel):
    def __init__(self, parent, token, on_submit):
        super().__init__(parent)
        self.title("Проверка PIN")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.on_submit = on_submit
        body = ttk.Frame(self, padding=18)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text=token.label or token.model, style="Section.TLabel").pack(anchor="w")
        ttk.Label(body, text=f"Осталось попыток: {token.user_pin_attempts}",
                  style="Muted.TLabel").pack(anchor="w", pady=(3, 13))
        ttk.Label(body, text="PIN").pack(anchor="w", pady=(0, 5))
        self.pin = tk.StringVar()
        entry = ttk.Entry(body, textvariable=self.pin, show="●", width=30)
        entry.pack(fill="x")
        ttk.Label(body, text="Неверный PIN уменьшит число оставшихся попыток.",
                  foreground="#a15c00").pack(anchor="w", pady=(10, 0))
        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(16, 0))
        action_button(buttons, "Отмена", self.destroy).pack(side="right")
        action_button(buttons, "Проверить", self._submit).pack(side="right", padx=(0, 7))
        entry.focus_set()
        self.bind("<Escape>", lambda _event: self.destroy())
        self.bind("<Return>", lambda _event: self._submit())

    def _submit(self):
        pin = self.pin.get()
        if not pin:
            messagebox.showerror("Проверка PIN", "Введи PIN.", parent=self)
            return
        self.pin.set("")
        self.destroy()
        self.on_submit(pin)


class RequestDialog(CenteredToplevel):
    def __init__(self, parent, token, on_submit):
        super().__init__(parent)
        self.title("Создать ключ и запрос")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.on_submit = on_submit
        body = ttk.Frame(self, padding=18)
        body.pack(fill="both", expand=True)
        import getpass
        server_name = parent.settings.server_address.strip()
        self.common_name = tk.StringVar(value="")
        self.key_label = tk.StringVar(value="Vovan-T RDP")
        self.certificate_label = tk.StringVar(value=server_name)
        self.organization = tk.StringVar(value="Vovan-T")
        self.org_unit = tk.StringVar(value="Token Manager")
        self.country = tk.StringVar(value="RU")
        self.subject_serial = tk.StringVar(value=token.serial)
        self.upn = tk.StringVar(value=f"{getpass.getuser()}@{server_name}")
        self.token = token
        if token.vendor == "ISBC":
            options = token.key_options
        elif token.vendor == "Aktiv" and supports_rutoken_sdk(token.model):
            try:
                options = tuple(f"RSA:{size}" for size in
                                rutoken_rsa_key_sizes(token.serial, token.model))
            except Exception:
                options = ("RSA:2048",)
        else:
            options = ("RSA:2048",)
        if not options:
            options = ("ECDSA:256",) if token.vendor == "ISBC" else ("RSA:2048",)
        self.algorithm = tk.StringVar(value=options[0])
        for label, variable in (("Название сертификата (CN) — обязательно", self.common_name),
                                ("Название ключа на токене", self.key_label),
                                ("Название сертификата на токене", self.certificate_label),
                                ("UPN — учётное имя", self.upn)):
            ttk.Label(body, text=label).pack(anchor="w", pady=(0, 5))
            ttk.Entry(body, textvariable=variable, width=46).pack(fill="x", pady=(0, 12))
        subject = ttk.LabelFrame(body, text="Поля CSR", padding=10)
        subject.pack(fill="x", pady=(0, 12))
        for index, (label, variable) in enumerate((("O — организация", self.organization),
                                                   ("OU — подразделение", self.org_unit),
                                                   ("C — страна", self.country),
                                                   ("SERIALNUMBER — серийный идентификатор", self.subject_serial))):
            row, pair = divmod(index, 2)
            column = pair * 2
            ttk.Label(subject, text=label).grid(row=row, column=column, sticky="w", padx=(0, 6), pady=3)
            ttk.Entry(subject, textvariable=variable, width=19).grid(
                row=row, column=column + 1, sticky="ew", padx=(0, 10) if pair == 0 else 0, pady=3)
        subject.columnconfigure(1, weight=1)
        subject.columnconfigure(3, weight=1)
        ttk.Label(body, text="Алгоритм ключа").pack(anchor="w", pady=(0, 5))
        ttk.Combobox(body, textvariable=self.algorithm, values=options,
                     state="readonly", width=16).pack(anchor="w")
        self.pin = tk.StringVar()
        ttk.Label(body, text="PIN токена").pack(anchor="w", pady=(12, 5))
        ttk.Entry(body, textvariable=self.pin, show="●", width=30).pack(fill="x")
        if token.vendor == "ISBC":
            note = "Поддерживаемые алгоритмы прочитаны с выбранного ESMART. RSA-1024 устарел; используй ECDSA-256."
        elif token.vendor == "Aktiv" and supports_rutoken_sdk(token.model):
            note = "Ключ и CSR будут созданы через SDK непосредственно на выбранном Rutoken. Ключ нельзя экспортировать."
        else:
            note = ("Для неизвестного типа используется Windows Smart Card KSP. "
                    "Windows может повторно запросить PIN в системном окне.")
        ttk.Label(body, text=note, style="Muted.TLabel", wraplength=420).pack(anchor="w", pady=(13, 0))
        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(17, 0))
        action_button(buttons, "Отмена", self.destroy).pack(side="right")
        action_button(buttons, "Создать", self._submit).pack(side="right", padx=(0, 7))

    def _submit(self):
        cn = self.common_name.get().strip()
        key_label = self.key_label.get().strip()
        certificate_label = self.certificate_label.get().strip()
        organization = self.organization.get().strip()
        org_unit = self.org_unit.get().strip()
        country = self.country.get().strip().upper()
        subject_serial = self.subject_serial.get().strip()
        upn = self.upn.get().strip()
        if not cn:
            messagebox.showerror("Создание запроса", "Укажи CN.", parent=self)
            return
        if not key_label or not certificate_label:
            messagebox.showerror("Создание запроса", "Укажи названия ключа и сертификата.", parent=self)
            return
        if country and len(country) != 2:
            messagebox.showerror("Создание запроса", "Страна должна состоять из двух букв.", parent=self)
            return
        if upn and ("@" not in upn or upn.startswith("@") or upn.endswith("@")):
            messagebox.showerror("Создание запроса", "UPN должен иметь вид name@example.org.", parent=self)
            return
        algorithm = self.algorithm.get()
        pin = self.pin.get()
        if not pin:
            messagebox.showerror("Создание запроса", "Введи PIN токена.", parent=self)
            return
        self.pin.set("")
        self.destroy()
        subject_fields = {"CN": cn, "O": organization, "OU": org_unit,
                          "C": country, "serialNumber": subject_serial}
        self.on_submit(cn, upn, key_label, certificate_label, subject_fields, algorithm, pin)


class CertificateLabelsDialog(CenteredToplevel):
    def __init__(self, parent, key_label, certificate_label, on_submit):
        super().__init__(parent)
        self.title("Названия объектов токена")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.on_submit = on_submit
        body = ttk.Frame(self, padding=18)
        body.pack(fill="both", expand=True)
        self.key_label = tk.StringVar(value=key_label)
        self.certificate_label = tk.StringVar(value=certificate_label)
        for label, variable in (("Название ключа", self.key_label),
                                ("Название сертификата", self.certificate_label)):
            ttk.Label(body, text=label).pack(anchor="w", pady=(0, 5))
            ttk.Entry(body, textvariable=variable, width=48).pack(fill="x", pady=(0, 12))
        ttk.Label(body, text="Предложено центром или взято из CN. Можно изменить.",
                  style="Muted.TLabel").pack(anchor="w")
        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(17, 0))
        action_button(buttons, "Отмена", self.destroy).pack(side="right")
        action_button(buttons, "Продолжить", self._submit).pack(side="right", padx=(0, 7))

    def _submit(self):
        key_label = self.key_label.get().strip()
        certificate_label = self.certificate_label.get().strip()
        if not key_label or not certificate_label:
            messagebox.showerror("Названия объектов", "Заполни оба названия.", parent=self)
            return
        if len(key_label.encode("utf-8")) > 64 or len(certificate_label.encode("utf-8")) > 64:
            messagebox.showerror("Названия объектов", "Название не должно превышать 64 байта UTF-8.", parent=self)
            return
        self.destroy()
        self.on_submit(key_label, certificate_label)


def _certificate_input(path: Path):
    temporary = None
    key_label = ""
    certificate_label = ""
    certificate_path = path
    if path.suffix.lower() == ".zip":
        try:
            with zipfile.ZipFile(path) as archive:
                metadata = json.loads(archive.read("token-metadata.json").decode("utf-8"))
                if metadata.get("format") != "vovan-t-token-certificate" or metadata.get("version") != 1:
                    raise ValueError("неизвестный формат метаданных")
                certificate_name = metadata.get("certificateFile", "")
                if not certificate_name or Path(certificate_name).name != certificate_name:
                    raise ValueError("некорректное имя сертификата")
                certificate_bytes = archive.read(certificate_name)
                key_label = str(metadata.get("keyLabel", "")).strip()
                certificate_label = str(metadata.get("certificateLabel", "")).strip()
        except (KeyError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
            raise RuntimeError(f"ZIP не является комплектом KPI для токена: {exc}") from exc
        temporary = tempfile.TemporaryDirectory(prefix="vovan-t-token-")
        certificate_path = Path(temporary.name) / Path(certificate_name).name
        certificate_path.write_bytes(certificate_bytes)
    raw = certificate_path.read_bytes()
    try:
        certificate = x509.load_pem_x509_certificate(raw)
    except ValueError:
        try:
            certificate = x509.load_der_x509_certificate(raw)
        except ValueError as exc:
            if temporary:
                temporary.cleanup()
            raise RuntimeError("Файл не содержит сертификат X.509 в PEM или DER") from exc
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    common_name = common_names[0].value if common_names else "Certificate"
    return certificate_path, temporary, key_label or common_name, certificate_label or common_name


class ChangePinDialog(CenteredToplevel):
    def __init__(self, parent, token, on_submit):
        super().__init__(parent)
        self.title("Сменить PIN")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.on_submit = on_submit
        body = ttk.Frame(self, padding=18)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text=token.label or token.model, style="Section.TLabel").pack(anchor="w", pady=(0, 12))
        self.old_pin, self.new_pin, self.repeat_pin = tk.StringVar(), tk.StringVar(), tk.StringVar()
        for label, variable in (("Текущий PIN", self.old_pin), ("Новый PIN", self.new_pin),
                                ("Повтори новый PIN", self.repeat_pin)):
            ttk.Label(body, text=label).pack(anchor="w", pady=(0, 4))
            ttk.Entry(body, textvariable=variable, show="●", width=32).pack(fill="x", pady=(0, 10))
        ttk.Label(body, text="Неверный текущий PIN уменьшит число попыток.",
                  foreground="#a15c00").pack(anchor="w")
        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(16, 0))
        action_button(buttons, "Отмена", self.destroy).pack(side="right")
        action_button(buttons, "Сменить", self._submit).pack(side="right", padx=(0, 7))

    def _submit(self):
        old_pin, new_pin, repeat_pin = self.old_pin.get(), self.new_pin.get(), self.repeat_pin.get()
        if not old_pin or not new_pin:
            messagebox.showerror("Смена PIN", "Заполни все поля.", parent=self)
            return
        if new_pin != repeat_pin:
            messagebox.showerror("Смена PIN", "Новые PIN не совпадают.", parent=self)
            return
        self.old_pin.set(""); self.new_pin.set(""); self.repeat_pin.set("")
        self.destroy()
        self.on_submit(old_pin, new_pin)


class InitializeDialog(CenteredToplevel):
    def __init__(self, parent, token, on_submit):
        super().__init__(parent)
        self.title("Инициализировать токен")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.token = token
        self.on_submit = on_submit
        body = ttk.Frame(self, padding=18)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="ВСЕ КЛЮЧИ И СЕРТИФИКАТЫ БУДУТ УДАЛЕНЫ",
                  foreground="#b42318", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 12))
        self.label = tk.StringVar(value=token.label or "RDP-Token")
        self.so_pin, self.user_pin, self.repeat_pin = tk.StringVar(), tk.StringVar(), tk.StringVar()
        fields = (("Метка токена", self.label, False), ("Текущий Admin/SO PIN", self.so_pin, True),
                  ("Новый User PIN", self.user_pin, True), ("Повтори User PIN", self.repeat_pin, True))
        for text, variable, secret in fields:
            ttk.Label(body, text=text).pack(anchor="w", pady=(0, 4))
            ttk.Entry(body, textvariable=variable, show="●" if secret else "", width=40).pack(fill="x", pady=(0, 9))
        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(14, 0))
        action_button(buttons, "Отмена", self.destroy).pack(side="right")
        action_button(buttons, "УДАЛИТЬ ВСЁ И ИНИЦИАЛИЗИРОВАТЬ",
                      self._submit).pack(side="right", padx=(0, 7))

    def _submit(self):
        if not self.so_pin.get() or not self.user_pin.get() or not self.label.get().strip():
            messagebox.showerror("Инициализация", "Заполни все поля.", parent=self)
            return
        if self.user_pin.get() != self.repeat_pin.get():
            messagebox.showerror("Инициализация", "Новые User PIN не совпадают.", parent=self)
            return
        if not messagebox.askyesno("Инициализация",
            "Уверен? Инициализация удалит все ключи и сертификаты с выбранного токена.", parent=self):
            return
        label, so_pin, user_pin = self.label.get().strip(), self.so_pin.get(), self.user_pin.get()
        self.so_pin.set(""); self.user_pin.set(""); self.repeat_pin.set("")
        self.destroy()
        self.on_submit(label, so_pin, user_pin)


class FormatDialog(CenteredToplevel):
    def __init__(self, parent, token, on_submit):
        super().__init__(parent)
        self.title("Форматировать токен")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.on_submit = on_submit
        body = ttk.Frame(self, padding=18)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="ФОРМАТИРОВАНИЕ УДАЛИТ ВСЁ БЕЗ ВОЗМОЖНОСТИ ВОССТАНОВЛЕНИЯ",
                  foreground="#b42318", font=("Segoe UI", 10, "bold"),
                  wraplength=470).pack(anchor="w", pady=(0, 12))
        self.label = tk.StringVar(value=token.label or "Rutoken")
        self.current_admin = tk.StringVar()
        self.new_admin = tk.StringVar()
        self.new_admin_repeat = tk.StringVar()
        self.new_user = tk.StringVar()
        self.new_user_repeat = tk.StringVar()
        fields = (("Метка токена", self.label, False),
                  ("Текущий Admin PIN", self.current_admin, True),
                  ("Новый Admin PIN", self.new_admin, True),
                  ("Повтори новый Admin PIN", self.new_admin_repeat, True),
                  ("Новый User PIN", self.new_user, True),
                  ("Повтори новый User PIN", self.new_user_repeat, True))
        for text, variable, secret in fields:
            ttk.Label(body, text=text).pack(anchor="w", pady=(0, 4))
            ttk.Entry(body, textvariable=variable, show="●" if secret else "", width=42).pack(fill="x", pady=(0, 9))
        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(14, 0))
        action_button(buttons, "Отмена", self.destroy).pack(side="right")
        action_button(buttons, "Форматировать", self._submit).pack(side="right", padx=(0, 7))

    def _submit(self):
        if not all((self.label.get().strip(), self.current_admin.get(), self.new_admin.get(), self.new_user.get())):
            messagebox.showerror("Форматирование", "Заполни все поля.", parent=self)
            return
        if self.new_admin.get() != self.new_admin_repeat.get():
            messagebox.showerror("Форматирование", "Новые Admin PIN не совпадают.", parent=self)
            return
        if self.new_user.get() != self.new_user_repeat.get():
            messagebox.showerror("Форматирование", "Новые User PIN не совпадают.", parent=self)
            return
        if not messagebox.askyesno("Форматирование", "Уверен, что нужно полностью форматировать токен?", parent=self):
            return
        values = (self.label.get().strip(), self.current_admin.get(), self.new_admin.get(), self.new_user.get())
        for variable in (self.current_admin, self.new_admin, self.new_admin_repeat,
                         self.new_user, self.new_user_repeat):
            variable.set("")
        self.destroy()
        self.on_submit(*values)


class InfoDialog(CenteredToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("О программе")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        body = ttk.Frame(self, padding=20)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text=APP_NAME, style="Title.TLabel").pack(anchor="w")
        ttk.Label(body, text=APP_BRAND, style="Muted.TLabel").pack(anchor="w", pady=(2, 0))
        ttk.Label(body, text=f"Версия: {APP_VERSION}", style="Value.TLabel").pack(anchor="w", pady=(4, 16))
        ttk.Label(body, text="Поддерживаемые токены", style="Section.TLabel").pack(anchor="w", pady=(0, 7))
        for item in SUPPORTED_TOKENS:
            ttk.Label(body, text=f"• {item}", wraplength=590, justify="left").pack(anchor="w", pady=3)
        ttk.Label(body, text="Операции записи выполняются только после нажатия соответствующей кнопки.",
                  style="Muted.TLabel", wraplength=590).pack(anchor="w", pady=(16, 0))
        action_button(body, "Закрыть", self.destroy).pack(anchor="e", pady=(18, 0))


class DetailsDialog(CenteredToplevel):
    def __init__(self, parent, heading, fields):
        super().__init__(parent)
        self.title(heading)
        self.transient(parent)
        self.resizable(True, False)
        body = ttk.Frame(self, padding=18)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text=heading, style="Section.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 10)
        )
        for row, (title, value) in enumerate(fields, start=1):
            if title.startswith("# "):
                ttk.Label(body, text=title[2:], style="Section.TLabel").grid(
                    row=row, column=0, columnspan=2, sticky="w", padx=(0, 20), pady=(10, 6)
                )
                continue
            ttk.Label(body, text=title, style="Muted.TLabel").grid(
                row=row, column=0, sticky="nw", padx=(0, 20), pady=4
            )
            ttk.Label(body, text=str(value or "—"), style="Value.TLabel", wraplength=520).grid(
                row=row, column=1, sticky="nw", pady=4
            )
        body.columnconfigure(1, weight=1)
        action_button(body, "Закрыть", self.destroy).grid(
            row=len(fields) + 1, column=1, sticky="e", pady=(16, 0)
        )


class TokenAdmin(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self._set_application_icon()
        self.geometry("1120x580")
        self.minsize(900, 480)
        self.tokens = []
        self.selected_token = None
        self.settings = load_settings()
        self._configure_style()
        self.icons = load_icons(self)
        self._build_ui()
        self.after(120, self.refresh)

    def _set_application_icon(self):
        assets = resource_root() / "assets"
        try:
            self._application_icon = tk.PhotoImage(file=str(assets / "token_access.png"))
            self.iconphoto(True, self._application_icon)
        except tk.TclError:
            self._application_icon = None
        try:
            self.iconbitmap(default=str(assets / "token_access.ico"))
        except tk.TclError:
            pass

    def _configure_style(self):
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Title.TLabel", font=("Segoe UI", 18, "bold"))
        style.configure("Section.TLabel", font=("Segoe UI", 11, "bold"))
        style.configure("Value.TLabel", font=("Segoe UI", 10, "bold"), foreground="#173f66")
        style.configure("Muted.TLabel", foreground="#66758a")
        style.configure("Treeview", rowheight=34, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def _build_ui(self):
        self.main_tabs = ttk.Notebook(self)
        self.main_tabs.pack(fill="both", expand=True)
        token_page = ttk.Frame(self.main_tabs)
        self.main_tabs.add(token_page, text="Токены")

        heading = ttk.Frame(token_page, padding=(16, 13))
        heading.pack(fill="x")
        ttk.Label(heading, text="Токены", style="Title.TLabel").pack(side="left")
        ttk.Label(heading, text="Безопасное локальное управление", style="Muted.TLabel").pack(side="left", padx=14)
        self.server_button = tk.Button(
            heading, command=self.open_server, relief="raised", borderwidth=2,
            background="#e7e9ed", activebackground="#d4d9e1", foreground="#20252c",
            activeforeground="#20252c", cursor="hand2", font=("Segoe UI", 9, "bold"),
            padx=9, pady=4,
        )
        self.server_button.pack(side="left", padx=(2, 12))
        ToolTip(self.server_button, "Открыть сервер в браузере")
        self._update_server_label()
        icon_button(heading, self.icons["info"], lambda: InfoDialog(self),
                    "Информация").pack(side="right")
        icon_button(heading, self.icons["settings"], self.open_settings,
                    "Настройки").pack(side="right", padx=(0, 7))
        icon_button(heading, self.icons["refresh"], self.refresh,
                    "Обновить список токенов").pack(side="right", padx=(0, 7))

        content = ttk.Panedwindow(token_page, orient="horizontal")
        content.pack(fill="both", expand=True, padx=16, pady=(0, 10))
        left = ttk.Labelframe(content, text="Подключённые", padding=8)
        right = ttk.Labelframe(content, text="Выбранный токен", padding=14)
        self.right_panel = right
        content.add(left, weight=2)
        content.add(right, weight=3)

        actions = ttk.Frame(right)
        actions.pack(fill="x", pady=(0, 12))
        primary_actions = ttk.Frame(actions)
        primary_actions.pack(fill="x")
        admin_actions = ttk.Frame(actions)
        admin_actions.pack(fill="x", pady=(7, 0))
        token_button = {}
        self.pin_action = action_button(primary_actions, "Проверить PIN", self.open_pin,
                                        state="disabled", **token_button)
        self.pin_action.pack(side="left", padx=(0, 7))
        self.request_action = action_button(primary_actions, "Ключ + CSR", self.open_request,
                                            state="disabled", **token_button)
        self.request_action.pack(side="left", padx=(0, 7))
        self.install_action = action_button(primary_actions, "Установить сертификат",
                                            self.install_certificate, state="disabled", **token_button)
        self.install_action.pack(side="left", padx=(0, 7))
        self.change_pin_action = action_button(admin_actions, "Сменить PIN", self.open_change_pin,
                                               state="disabled", **token_button)
        self.change_pin_action.pack(side="left")
        self.rename_action = action_button(admin_actions, "Переименовать", self.open_rename,
                                           **token_button)
        self.rename_action.pack(side="left", padx=(7, 0))
        ToolTip(self.rename_action, "Изменить физическую метку токена")
        self.initialize_action = action_button(admin_actions, "Очистить и настроить",
                                                self.open_initialize, state="disabled", **token_button)
        self.initialize_action.pack(side="left", padx=(7, 0))
        self.format_action = action_button(admin_actions, "Форматировать", self.open_format,
                                           state="disabled", **token_button)
        self.format_action.pack(side="left", padx=(7, 0))

        columns = ("name", "vendor", "serial", "state")
        self.table = ttk.Treeview(left, columns=columns, show="headings", selectmode="browse")
        for name, title, width in (
            ("name", "Токен", 145), ("vendor", "Тип", 165),
            ("serial", "Серийный номер", 125), ("state", "Состояние", 68),
        ):
            self.table.heading(name, text=title)
            self.table.column(name, width=width, minwidth=65)
        self.table.pack(fill="both", expand=True)
        self.table.bind("<<TreeviewSelect>>", self._select_token)
        self.show_empty = tk.BooleanVar(value=False)
        ttk.Checkbutton(left, text="Показывать пустые считыватели", variable=self.show_empty,
                        command=self._fill_table).pack(anchor="w", pady=(8, 0))

        self.current_detail_heading = "Информация о токене"
        self.current_detail_fields = ()
        self.detail_heading = action_button(
            right, "Информация о токене...", self._show_details_dialog
        )
        self.detail_heading.pack(anchor="w", pady=(0, 5))

        ttk.Separator(right).pack(fill="x", pady=12)
        ttk.Label(right, text="Содержимое", style="Section.TLabel").pack(anchor="w", pady=(0, 7))
        self.objects = ttk.Treeview(right, columns=("type", "label", "id"), show="headings", height=5)
        for name, title, width in (("type", "Тип", 120), ("label", "Название", 250), ("id", "ID", 180)):
            self.objects.heading(name, text=title)
            self.objects.column(name, width=width)
        self.objects.pack(fill="both", expand=True)
        self.objects.bind("<<TreeviewSelect>>", self._object_selected)
        object_actions = ttk.Frame(right)
        object_actions.pack(fill="x", pady=(7, 0))
        self.delete_object_action = action_button(
            object_actions, "Удалить выбранный объект", self.confirm_delete_object,
            state="disabled",
        )
        self.delete_object_action.pack(side="right")
        action_button(object_actions, "Экспорт токена...", self.export_token_card).pack(side="left")

        self.status = ttk.Label(token_page, padding=(16, 8), relief="sunken", anchor="w",
                                text=f"ОС: {platform.system()} · ожидание сканирования")
        self.status.pack(fill="x")
        self.management = ManagementFrame(
            self.main_tabs,
            lambda: self.settings,
            lambda: self.selected_token,
            self._management_inventory,
            lambda token, callback: PinDialog(self, token, callback),
            self.icons,
        )
        self.main_tabs.add(self.management, text="Управление")

    def _show_details_dialog(self):
        DetailsDialog(self, self.current_detail_heading, self.current_detail_fields)

    def _management_inventory(self):
        self.refresh()
        return list(self.tokens)

    def open_settings(self):
        SettingsDialog(self, self.settings, self._save_settings)

    def open_server(self):
        if not self.settings.server_address.strip():
            self.open_settings()
            return
        port = "" if self.settings.server_port == 443 else f":{self.settings.server_port}"
        webbrowser.open(f"https://{self.settings.server_address}{port}/")

    def open_pin(self):
        if self.selected_token and self.selected_token.state == "READY":
            PinDialog(self, self.selected_token, self._verify_pin)

    def open_request(self):
        if self.selected_token and self.selected_token.state == "READY":
            RequestDialog(self, self.selected_token, self._create_request)

    def open_change_pin(self):
        if self.selected_token and self.selected_token.state == "READY":
            ChangePinDialog(self, self.selected_token, self._change_pin)

    def open_rename(self):
        token = self.selected_token
        if token is None or token.state != "READY":
            return
        if token.vendor != "Aktiv":
            messagebox.showinfo(
                "Переименование токена",
                "eSmart нельзя безопасно переименовать без полной инициализации.",
                parent=self,
            )
            return
        label = simpledialog.askstring(
            "Переименование токена", "Новая метка:",
            initialvalue=token.label or "Rutoken", parent=self,
        )
        if label and label.strip():
            PinDialog(self, token, lambda pin: self._rename_token(label.strip(), pin))

    def _rename_token(self, label, pin):
        token = self.selected_token
        if token is None:
            return
        self.status.configure(text=f"Переименование {token.label or token.model}…")
        self.update_idletasks()
        try:
            set_rutoken_label(token.serial, pin, label)
        except Exception as exc:
            messagebox.showerror("Переименование токена", str(exc), parent=self)
            self.refresh()
            return
        messagebox.showinfo("Переименование токена", f"Новая метка: {label}", parent=self)
        self.refresh()

    def open_initialize(self):
        if self.selected_token and self.selected_token.state == "READY":
            InitializeDialog(self, self.selected_token, self._initialize_token)

    def open_format(self):
        if self.selected_token and self.selected_token.state == "READY" and self.selected_token.vendor == "Aktiv":
            FormatDialog(self, self.selected_token, self._format_token)

    def _format_token(self, label, current_admin_pin, new_admin_pin, new_user_pin):
        token = self.selected_token
        if token is None:
            return
        self.status.configure(text=f"Форматирование {token.label or token.model}…")
        self.update_idletasks()
        try:
            format_token(token.vendor, token.serial, label, current_admin_pin, new_admin_pin, new_user_pin)
        except Exception as exc:
            messagebox.showerror("Форматирование", str(exc), parent=self)
            self.refresh()
            return
        messagebox.showinfo("Форматирование", "Токен отформатирован.", parent=self)
        self.refresh()

    def _initialize_token(self, label, so_pin, user_pin):
        token = self.selected_token
        if token is None:
            return
        try:
            initialize_token(token.vendor, token.serial, label, so_pin, user_pin)
        except Exception as exc:
            messagebox.showerror("Инициализация", str(exc), parent=self)
            self.refresh()
            return
        messagebox.showinfo("Инициализация", "Токен очищен и инициализирован.", parent=self)
        self.refresh()

    def _change_pin(self, old_pin, new_pin):
        token = self.selected_token
        if token is None:
            return
        try:
            change_user_pin(token.vendor, token.serial, old_pin, new_pin)
        except Exception as exc:
            messagebox.showerror("Смена PIN", str(exc), parent=self)
            self.refresh()
            return
        messagebox.showinfo("Смена PIN", "PIN изменён.", parent=self)
        self.refresh()

    def export_token_card(self):
        token = self.selected_token
        if token is None:
            messagebox.showinfo("Экспорт токена", "Выбери токен и его сертификат.", parent=self)
            return
        certificates = [item for item in token.objects if all(item.get(key) for key in ("serial", "subject", "issuer"))]
        selected = None
        if self.objects.selection():
            item_id = self.objects.selection()[0]
            if item_id.startswith("object-"):
                item = token.objects[int(item_id.split("-", 1)[1])]
                if item in certificates:
                    selected = item
        if selected is None and len(certificates) == 1:
            selected = certificates[0]
        if selected is None:
            messagebox.showinfo("Экспорт токена", "Выбери нужный сертификат в «Содержимом».\nДля экспорта нужен выпущенный сертификат, не ключ и не CSR.", parent=self)
            return
        export_card(self, selected, token.label or selected.get("label") or "Новый токен")

    def _object_selected(self, _event=None):
        enabled = False
        selected_object = None
        if self.selected_token and self.objects.selection():
            item_id = self.objects.selection()[0]
            if item_id.startswith("object-"):
                selected_object = self.selected_token.objects[int(item_id.split("-", 1)[1])]
                enabled = "class" in selected_object and "id_hex" in selected_object
        self.delete_object_action.configure(state="normal" if enabled else "disabled")
        if selected_object:
            self._show_object_details(selected_object)
        else:
            self._show_token_details(self.selected_token)

    def _set_details(self, heading, fields):
        self.current_detail_heading = heading
        self.current_detail_fields = tuple(fields)
        button_text = "Информация о токене..." if heading == "Токен" else f"Информация: {heading}..."
        self.detail_heading.configure(text=button_text)

    def _show_token_details(self, token):
        fields = (
            ("Метка", getattr(token, "label", "")),
            ("Производитель", getattr(token, "vendor", "")),
            ("Модель", getattr(token, "model", "")),
            ("Серийный номер", getattr(token, "serial", "")),
            ("Считыватель", getattr(token, "reader", "")),
            ("ATR", getattr(token, "atr", "")),
            ("Память, свободно / всего", getattr(token, "memory", "")),
            ("Попытки PIN, осталось / всего", getattr(token, "user_pin_attempts", "")),
            ("Попытки Admin PIN, осталось / всего", getattr(token, "admin_pin_attempts", "")),
        ) if token else ()
        self._set_details("Токен", fields)

    def _show_object_details(self, item):
        object_type = str(item.get("type", item.get("class", "Объект")))
        normalized = object_type.lower()
        object_id = item.get("id", "—")
        related = []
        if self.selected_token:
            related = [candidate for candidate in self.selected_token.objects
                       if candidate is not item and candidate.get("id") == object_id]
        if "certificate" in normalized or "сертификат" in normalized:
            heading = "Сертификат"
            subject_fields = tuple((field.get("name", "OID"), field.get("value", ""))
                                   for field in item.get("subject_fields", ()))
            issuer_fields = tuple((field.get("name", "OID"), field.get("value", ""))
                                  for field in item.get("issuer_fields", ()))
            fields = (
                ("Название", item.get("label")),
                ("ID", object_id),
                ("# Subject", ""),
            ) + (subject_fields or (("Полный DN", item.get("subject_cn") or item.get("subject")),)) + (
                ("# Issuer", ""),
            ) + (issuer_fields or (("Полный DN", item.get("issuer_cn") or item.get("issuer")),)) + (
                ("# Параметры X.509", ""),
                ("Серийный номер сертификата", item.get("serial")),
                ("Ключ", item.get("key_type")),
                ("Провайдер", item.get("provider")),
                ("Контейнер", item.get("container")),
                ("Источник", item.get("source")),
                ("Действует с", self._display_date(item.get("not_before_date"))),
                ("Действует до", self._display_date(item.get("not_after_date"))),
                ("SHA-1", item.get("fingerprint")),
                ("SHA-256", item.get("fingerprint_sha256")),
            )
        elif "public key" in normalized or "открытый ключ" in normalized:
            certificate = next((candidate for candidate in related
                                if "certificate" in str(candidate.get("type", "")).lower()
                                or "сертификат" in str(candidate.get("type", "")).lower()), None)
            heading = "Открытый ключ"
            fields = (
                ("Название", item.get("label")),
                ("ID", object_id),
                ("Алгоритм", item.get("key_type") or item.get("algorithm")),
                ("Назначение", item.get("usage")),
                ("Провайдер", item.get("provider")),
                ("Контейнер", item.get("container")),
                ("Источник", item.get("source")),
                ("Связанный сертификат", "Да" if certificate else "Нет"),
                ("Сертификат Subject", (certificate or {}).get("subject_cn")),
                ("Сертификат Issuer", (certificate or {}).get("issuer_cn")),
                ("Сертификат действует до", self._display_date((certificate or {}).get("not_after_date"))),
                ("Отпечаток сертификата", (certificate or {}).get("fingerprint")),
            )
        else:
            heading = object_type
            fields = (
                ("Название", item.get("label")), ("ID", object_id),
                ("Тип", object_type), ("Класс PKCS#11", item.get("class")),
            )
        self._set_details(heading, fields)

    @staticmethod
    def _object_type_label(value):
        return {
            "public key": "Открытый ключ", "private key": "Закрытый ключ",
            "certificate": "Сертификат", "secret key": "Секретный ключ",
            "data": "Данные",
        }.get(str(value).lower(), value)

    @staticmethod
    def _display_date(value):
        if not value:
            return ""
        try:
            return datetime.strptime(value, "%b %d %H:%M:%S %Y GMT").strftime("%d.%m.%Y %H:%M UTC")
        except ValueError:
            return value

    def confirm_delete_object(self):
        if not self.selected_token or not self.objects.selection():
            return
        item_id = self.objects.selection()[0]
        if not item_id.startswith("object-"):
            return
        index = int(item_id.split("-", 1)[1])
        item = self.selected_token.objects[index]
        if not messagebox.askyesno("Удаление объекта",
            f"Удалить только выбранный объект?\n\n{item.get('type')}\n{item.get('label')}\n\nОтменить это действие нельзя.",
            parent=self):
            return
        PinDialog(self, self.selected_token,
                  lambda pin: self._delete_object(item, pin))

    def _delete_object(self, item, pin):
        token = self.selected_token
        if token is None:
            return
        try:
            delete_object(token.vendor, token.serial, int(item["class"]), item["id_hex"], pin)
        except Exception as exc:
            messagebox.showerror("Удаление объекта", str(exc), parent=self)
            self.refresh()
            return
        messagebox.showinfo("Удаление объекта", "Выбранный объект удалён.", parent=self)
        self.refresh()

    def _create_request(self, common_name, upn, key_label, certificate_label,
                        subject_fields, algorithm, pin):
        token = self.selected_token
        if token is None:
            return
        safe_name = "".join(char if char.isalnum() or char in "-_" else "-" for char in common_name)
        output = filedialog.asksaveasfilename(parent=self, title="Сохранить запрос",
            defaultextension=".req", initialfile=f"{safe_name}.req",
            filetypes=(("Запрос сертификата", "*.req"), ("Все файлы", "*.*")))
        if not output:
            return
        request_path = Path(output)
        self.status.configure(text=f"Создание ключа и CSR для {common_name}…")
        self.update_idletasks()
        try:
            if token.vendor == "ISBC":
                path = create_esmart_request(token.serial, key_label, common_name, upn,
                                             algorithm, pin, request_path, subject_fields)
            elif token.vendor == "Aktiv" and supports_rutoken_sdk(token.model):
                key_length = int(algorithm.split(":", 1)[1])
                path = create_rutoken_request(token.serial, token.model, key_label,
                                              common_name, upn, key_length, pin, request_path,
                                              subject_fields)
            else:
                key_length = int(algorithm.split(":", 1)[1])
                path = create_smartcard_request(token.serial, key_label, common_name, upn,
                                                key_length, request_path, token.reader,
                                                subject_fields)
        except Exception as exc:
            messagebox.showerror("Создание запроса", str(exc), parent=self)
            self.status.configure(text="CSR не создан. Токены не перечитывались.")
            return
        messagebox.showinfo("Создание запроса", f"Ключ создан в токене.\nCSR сохранён:\n{path}", parent=self)
        self.refresh()

    def install_certificate(self):
        token = self.selected_token
        if token is None:
            return
        path = filedialog.askopenfilename(parent=self, title="Выбери подписанный сертификат",
            filetypes=(("Сертификат или комплект KPI", "*.cer *.crt *.pem *.zip"),
                       ("Все файлы", "*.*")))
        if not path:
            return
        if token.vendor == "ISBC":
            PinDialog(self, token, lambda pin: self._install_esmart_certificate(Path(path), pin))
            return
        if token.vendor == "Aktiv":
            try:
                cert_path, temporary, key_label, certificate_label = _certificate_input(Path(path))
            except Exception as exc:
                messagebox.showerror("Установка сертификата", str(exc), parent=self)
                return
            CertificateLabelsDialog(self, key_label, certificate_label,
                lambda selected_key_label, selected_certificate_label:
                    PinDialog(self, token, lambda pin: self._install_rutoken_certificate(
                        cert_path, pin, selected_key_label, selected_certificate_label, temporary)))
            return
        self.status.configure(text="Установка сертификата…")
        self.update_idletasks()
        try:
            install_smartcard_certificate(Path(path))
        except Exception as exc:
            messagebox.showerror("Установка сертификата", str(exc), parent=self)
            self.refresh()
            return
        messagebox.showinfo("Установка сертификата", "Сертификат установлен.", parent=self)
        self.refresh()

    def _install_rutoken_certificate(self, path, pin, key_label, certificate_label, temporary=None):
        token = self.selected_token
        if token is None:
            return
        self.status.configure(text="Проверка PIN и установка сертификата на Rutoken…")
        self.update_idletasks()
        try:
            install_rutoken_certificate(
                token.serial, token.model, token.label, path, pin,
                key_label, certificate_label)
        except Exception as exc:
            messagebox.showerror("Установка сертификата", str(exc), parent=self)
            self.status.configure(text="Сертификат не установлен. Токены не перечитывались.")
            return
        finally:
            if temporary is not None:
                temporary.cleanup()
        messagebox.showinfo("Установка сертификата", "Сертификат установлен на Rutoken.", parent=self)
        self.refresh()

    def _install_esmart_certificate(self, path, pin):
        token = self.selected_token
        if token is None:
            return
        self.status.configure(text="Установка сертификата на ESMART…")
        self.update_idletasks()
        try:
            install_esmart_certificate(token.serial, path, pin)
        except Exception as exc:
            messagebox.showerror("Установка сертификата", str(exc), parent=self)
            self.refresh()
            return
        messagebox.showinfo("Установка сертификата", "Сертификат установлен на ESMART.", parent=self)
        self.refresh()

    def _verify_pin(self, pin):
        token = self.selected_token
        if token is None:
            return
        self.status.configure(text=f"Проверка PIN: {token.label or token.model}…")
        self.update_idletasks()
        try:
            verify_user_pin(token.vendor, token.serial, pin)
        except Exception as exc:
            messagebox.showerror("Проверка PIN", str(exc), parent=self)
            self.refresh()
            return
        messagebox.showinfo("Проверка PIN", "PIN принят. Токен работает.", parent=self)
        self.refresh()

    def _save_settings(self, settings):
        try:
            save_settings(settings)
        except OSError as exc:
            messagebox.showerror("Настройки", f"Не удалось сохранить настройки:\n{exc}", parent=self)
            return
        self.settings = settings
        self._update_server_label()

    def _update_server_label(self):
        if not self.settings.server_address.strip():
            self.server_button.configure(text="Сервер не настроен")
            return
        port = "" if self.settings.server_port == 443 else f":{self.settings.server_port}"
        self.server_button.configure(text=f"https://{self.settings.server_address}{port}")

    def refresh(self):
        self.status.configure(text="Сканирование токенов…")
        self.update_idletasks()
        try:
            self.tokens, warnings = scan_inventory()
        except Exception as exc:
            self.tokens = []
            self.status.configure(text=f"Ошибка: {exc}")
            self._fill_table()
            return
        self._fill_table()
        ready = sum(token.state == "READY" for token in self.tokens)
        empty = sum(token.state == "EMPTY" for token in self.tokens)
        suffix = f" · {'; '.join(warnings)}" if warnings else ""
        self.status.configure(text=f"Подключено токенов: {ready} · пустых считывателей: {empty}{suffix}")

    def _visible_tokens(self):
        return self.tokens if self.show_empty.get() else [token for token in self.tokens if token.state == "READY"]

    def _fill_table(self):
        selected_reader = ""
        selection = self.table.selection()
        if selection:
            tags = self.table.item(selection[0], "tags")
            selected_reader = tags[0] if tags else ""
        self.table.delete(*self.table.get_children())
        selected_item = None
        for index, token in enumerate(self._visible_tokens()):
            item = self.table.insert("", "end", iid=f"token-{index}",
                values=(token.label or token.model or token.reader, token.model or token.vendor,
                        token.serial or "—",
                        "Готов" if token.state == "READY" else "Пусто"), tags=(token.reader,))
            if token.reader == selected_reader:
                selected_item = item
        children = self.table.get_children()
        if selected_item or children:
            item = selected_item or children[0]
            self.table.selection_set(item)
            self.table.focus(item)
            self._select_token()
        else:
            self._show_token(None)

    def _select_token(self, _event=None):
        selection = self.table.selection()
        if not selection:
            self._show_token(None)
            return
        tags = self.table.item(selection[0], "tags")
        reader = tags[0] if tags else ""
        self._show_token(next((token for token in self.tokens if token.reader == reader), None))

    def _show_token(self, token):
        self.selected_token = token
        self.right_panel.configure(text=(token.label or token.model or "Выбранный токен") if token else "Выбранный токен")
        self.pin_action.configure(state="normal" if token and token.state == "READY" else "disabled")
        state = "normal" if token and token.state == "READY" else "disabled"
        self.request_action.configure(state=state)
        self.install_action.configure(state=state)
        self.change_pin_action.configure(state=state)
        self.rename_action.configure(state="normal" if token and token.state == "READY" else "disabled")
        if token and token.state == "READY" and token.vendor == "Aktiv":
            self.initialize_action.pack_forget()
            if not self.format_action.winfo_manager():
                self.format_action.pack(side="left", padx=(7, 0))
            self.format_action.configure(state="normal")
        else:
            self.format_action.pack_forget()
            if not self.initialize_action.winfo_manager():
                self.initialize_action.pack(side="left", padx=(7, 0))
            self.initialize_action.configure(state=state)
        self._show_token_details(token)
        self.objects.delete(*self.objects.get_children())
        self.delete_object_action.configure(state="disabled")
        if token:
            for index, item in enumerate(token.objects):
                self.objects.insert("", "end", iid=f"object-{index}", values=(
                    self._object_type_label(item.get("type", item.get("class", "Объект"))),
                    item.get("label", item.get("name", "—")), item.get("id", "—")))
            if not token.objects:
                self.objects.insert("", "end", iid="no-objects",
                                    values=("—", "Объекты не найдены", "—"))


def run():
    TokenAdmin().mainloop()
