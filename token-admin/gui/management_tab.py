import tkinter as tk
import queue
import threading
from tkinter import filedialog, messagebox, simpledialog, ttk

from adapters.server_admin import (
    admin_action, exchange_recovery_code, exchange_token_signature, load_admin_state,
    request_token_challenge,
)
from adapters.token_signing import sign_token_challenge
from gui.icons import CenteredToplevel, action_button
from core.token_exchange import load_file, normalize_serial
from gui.token_exchange_dialogs import ImportTokenDialog, export_card


class PhysicalTokenDialog(CenteredToplevel):
    def __init__(self, parent, candidates):
        super().__init__(parent)
        self.title("Добавить токен")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.result = None
        self.candidates = candidates
        body = ttk.Frame(self, padding=18)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Новые токены", style="Section.TLabel").pack(anchor="w")
        ttk.Label(
            body,
            text="Выбери сертификат, который нужно зарегистрировать на сервере.",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(3, 10))
        self.choice = ttk.Combobox(
            body,
            state="readonly",
            width=76,
            values=[item["display"] for item in candidates],
        )
        self.choice.pack(fill="x")
        if candidates:
            self.choice.current(0)
        else:
            ttk.Label(body, text="Новых подключённых токенов нет. Можно добавить из файла.").pack(anchor="w", pady=(8, 0))
        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(16, 0))
        action_button(buttons, "Отмена", self.destroy).pack(side="right")
        action_button(buttons, "Добавить", self._accept).pack(side="right", padx=(0, 7))
        action_button(buttons, "Из файла...", self._from_file).pack(side="left")

    def _from_file(self):
        self.result = {"action": "token_import_file"}
        self.destroy()

    def _accept(self):
        index = self.choice.current()
        if index >= 0:
            self.result = self.candidates[index]
        self.destroy()


class RecoveryLoginDialog(CenteredToplevel):
    COMMAND = "sudo docker exec rdp-token-app recovery"

    def __init__(self, parent):
        super().__init__(parent)
        self.title("Аварийный вход")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.result = None
        body = ttk.Frame(self, padding=18)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text=self.COMMAND, font=("Consolas", 10)).pack(anchor="w", pady=(0, 9))
        self.code = ttk.Entry(body, width=82, font=("Consolas", 10))
        self.code.pack(fill="x")
        self.code.focus_set()
        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(14, 0))
        action_button(buttons, "Отмена", self.destroy).pack(side="right")
        action_button(buttons, "Войти", self._accept).pack(side="right", padx=(0, 7))
        self.bind("<Return>", self._accept)
        self.bind("<Escape>", lambda _event: self.destroy())

    def _accept(self, _event=None):
        value = self.code.get().strip()
        if value:
            self.result = value
            self.destroy()


class CrlDialog(CenteredToplevel):
    def __init__(self, parent, data, refresh_command):
        super().__init__(parent)
        self.title("CRL")
        self.resizable(False, False)
        self.transient(parent)
        self.refresh_command = refresh_command
        self.body = ttk.Frame(self, padding=18)
        self.body.pack(fill="both", expand=True)
        self.values = ttk.Frame(self.body)
        self.values.pack(fill="both", expand=True)
        buttons = ttk.Frame(self.body)
        buttons.pack(fill="x", pady=(16, 0))
        action_button(buttons, "Закрыть", self.destroy).pack(side="right")
        self.refresh_button = action_button(
            buttons, "Обновить CRL", self.refresh_command,
        )
        self.refresh_button.pack(side="right", padx=(0, 7))
        self.render(data)

    def render(self, data):
        for child in self.values.winfo_children():
            child.destroy()
        current = bool(data.get("current"))
        status_text = "✓ Актуален" if current else "× Требует внимания"
        status_color = "#176a42" if current else "#9f1f1b"
        ttk.Label(self.values, text="CRL", style="Section.TLabel").grid(
            row=0, column=0, sticky="w", pady=(0, 12),
        )
        tk.Label(
            self.values, text=status_text, foreground=status_color,
            font=("Segoe UI", 10, "bold"),
        ).grid(row=0, column=1, sticky="e", pady=(0, 12))
        rows = (
            ("Файл", data.get("file_name") or "—"),
            ("Издатель", data.get("issuer") or "—"),
            ("Выпущен", data.get("last_update") or "—"),
            ("Действует до", data.get("next_update") or "—"),
            ("Отозвано", str(data.get("revoked_count", 0))),
            ("Скачан", data.get("downloaded_at") or "—"),
            ("Публичный URL", data.get("url") or "—"),
            ("Локальная копия", data.get("local_file") or "—"),
        )
        for row, (label, value) in enumerate(rows, start=1):
            ttk.Label(self.values, text=label, style="Muted.TLabel").grid(
                row=row, column=0, sticky="nw", padx=(0, 18), pady=4,
            )
            ttk.Label(
                self.values, text=value, wraplength=560, justify="left",
            ).grid(row=row, column=1, sticky="nw", pady=4)
        error = data.get("error")
        if error:
            tk.Label(
                self.values, text=error, foreground="#9f1f1b",
                wraplength=680, justify="left",
            ).grid(row=len(rows) + 1, column=0, columnspan=2,
                   sticky="w", pady=(10, 0))

    def set_busy(self, busy):
        self.refresh_button.configure(state="disabled" if busy else "normal")


class ManagementFrame(ttk.Frame):
    def __init__(self, parent, settings_provider, token_provider, inventory_provider,
                 pin_requester, icons):
        super().__init__(parent, padding=12)
        self.settings_provider = settings_provider
        self.token_provider = token_provider
        self.inventory_provider = inventory_provider
        self.pin_requester = pin_requester
        self.icons = icons
        self.auth = None
        self.state = {}
        self._busy = False
        self._result_queue = queue.Queue()
        self._inline_edit = None
        self.crl_dialog = None
        self._build()

    def _build(self):
        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=(0, 10))
        self.status = ttk.Label(bar, text="Вход не выполнен", style="Muted.TLabel")
        action_button(bar, "Вход", self.login_certificate,
                      image=self.icons["login"], width=112).pack(side="left")
        action_button(bar, "Обновить", self.refresh,
                      image=self.icons["refresh"], width=134).pack(side="left")
        action_button(bar, "CRL", self.show_crl, width=86).pack(side="left", padx=(7, 0))
        self.status.pack(side="left", padx=(10, 0))
        action_button(bar, "Выход", self.logout,
                      image=self.icons["logout"], width=112).pack(side="right")
        action_button(bar, "Аварийный вход", self.login_recovery,
                      image=self.icons["emergency"], width=166).pack(side="right", padx=(0, 7))

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True)
        self.tokens_page, self.systems_page = ttk.Frame(self.tabs), ttk.Frame(self.tabs)
        self.ports_page, self.logs_page = ttk.Frame(self.tabs), ttk.Frame(self.tabs)
        self.tabs.add(self.tokens_page, text="Токены")
        self.tabs.add(self.systems_page, text="Системы")
        self.tabs.add(self.ports_page, text="Порты")
        self.tabs.add(self.logs_page, text="Журнал")
        self._build_tokens()
        self._build_systems()
        self._build_ports()
        self._build_logs()

    @staticmethod
    def _tree(parent, columns):
        tree = ttk.Treeview(parent, columns=[item[0] for item in columns], show="headings")
        for name, title, width in columns:
            tree.heading(name, text=title)
            tree.column(name, width=width, minwidth=70)
        tree.pack(fill="both", expand=True, padx=8, pady=8)
        return tree

    def _build_tokens(self):
        self.token_tree = self._tree(self.tokens_page, (
            ("label", "Название", 180), ("role", "Роль", 80), ("enabled", "Разрешён", 85),
            ("access", "Доступ", 250), ("serial", "Serial", 240),
            ("last_seen", "Последний вход", 170)))
        self.token_tree.bind("<Double-1>", self._begin_token_edit)
        self.token_tree.bind("<Button-1>", self._tree_click, add="+")
        bar = ttk.Frame(self.tokens_page, padding=8); bar.pack(fill="x")
        action_button(bar, "Добавить", self.approve_token).pack(side="left")
        action_button(bar, "Удалить", self.delete_token).pack(side="left", padx=7)
        self.token_edit_hint = ttk.Label(bar, text="Двойной щелчок — редактирование",
                                         style="Muted.TLabel")
        self.token_edit_hint.pack(side="right")
        self.token_edit_cancel = action_button(bar, "Отмена", self._cancel_inline_edit)
        self.token_edit_ok = action_button(bar, "ОК", self._commit_inline_edit)

    def _build_systems(self):
        self.system_tree = self._tree(self.systems_page, (
            ("name", "Система", 220), ("internal", "Внутренний адрес", 180),
            ("gateway", "Порт шлюза", 100), ("enabled", "Активна", 70)))
        self.system_tree.bind("<Double-1>", self._begin_system_edit)
        self.system_tree.bind("<Button-1>", self._tree_click, add="+")
        bar = ttk.Frame(self.systems_page, padding=8); bar.pack(fill="x")
        action_button(bar, "Добавить", self.add_system).pack(side="left")
        action_button(bar, "Удалить", self.delete_system).pack(side="left", padx=7)
        self.system_edit_hint = ttk.Label(bar, text="Двойной щелчок — редактирование",
                                          style="Muted.TLabel")
        self.system_edit_hint.pack(side="right")
        self.system_edit_cancel = action_button(bar, "Отмена", self._cancel_inline_edit)
        self.system_edit_ok = action_button(bar, "ОК", self._commit_inline_edit)

    def _build_ports(self):
        body = ttk.Frame(self.ports_page, padding=24); body.pack(anchor="nw")
        self.port_min, self.port_max = tk.StringVar(), tk.StringVar()
        ttk.Label(body, text="Диапазон портов шлюза", style="Section.TLabel").grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 12))
        ttk.Label(body, text="От").grid(row=1, column=0); ttk.Entry(body, textvariable=self.port_min, width=10).grid(row=1, column=1, padx=(6, 16))
        ttk.Label(body, text="До").grid(row=1, column=2); ttk.Entry(body, textvariable=self.port_max, width=10).grid(row=1, column=3, padx=6)
        action_button(body, "Сохранить", self.save_ports).grid(row=2, column=3, sticky="e", pady=(14, 0))
        self.port_info = ttk.Label(body, style="Muted.TLabel"); self.port_info.grid(row=3, column=0, columnspan=4, sticky="w", pady=(12, 0))

    def _build_logs(self):
        self.log_tree = self._tree(self.logs_page, (
            ("token", "Токен", 150), ("system", "Система", 160), ("source", "Источник", 130),
            ("state", "Состояние", 90), ("started", "Начало", 180), ("ended", "Окончание", 180)))

    def login_certificate(self):
        token = self.token_provider()
        if token is None:
            messagebox.showerror("Управление", "Сначала выбери физический токен во вкладке «Токены».", parent=self)
            return
        certificate = next((item for item in token.objects
                            if item.get("fingerprint") and item.get("certificate_pem")), None)
        if certificate is None:
            messagebox.showerror("Управление", "На выбранном токене не найден сертификат.", parent=self)
            return
        self.pin_requester(
            token,
            lambda pin: self._login_signed_challenge(token, certificate, pin),
        )

    def _login_signed_challenge(self, token, certificate, pin):
        settings = self.settings_provider()
        fingerprint = certificate["fingerprint"]

        def worker():
            challenge = request_token_challenge(settings, certificate["certificate_pem"])
            signature = sign_token_challenge(
                token, certificate, pin, challenge["challenge_bytes"])
            result = exchange_token_signature(
                settings, challenge["challenge_id"], signature)
            auth = {"session": result["session"], "certificate_fingerprint": fingerprint}
            return auth, load_admin_state(settings, auth)

        def success(result):
            self.auth, self.state = result
            self.status.configure(text="Вход по сертификату")
            self._fill()

        self._run_background(worker, success, "Проверка подписи токена")

    def login_recovery(self):
        dialog = RecoveryLoginDialog(self)
        self.wait_window(dialog)
        code = dialog.result
        if not code:
            return
        settings = self.settings_provider()

        def worker():
            result = exchange_recovery_code(settings, code.strip())
            auth = {"session": result["session"]}
            return auth, load_admin_state(settings, auth)

        def success(result):
            self.auth, self.state = result
            self.status.configure(text="Аварийная сессия")
            self._fill()

        self._run_background(worker, success, "Аварийный вход")

    def logout(self):
        self.auth, self.state = None, {}
        self.status.configure(text="Вход не выполнен")
        self._fill()

    def refresh(self):
        if self.auth:
            if not self._ensure_auth_device():
                return
            self._load()
        else:
            self.status.configure(text="Сначала выполни вход")

    def show_crl(self):
        if not self.auth:
            messagebox.showerror("CRL", "Сначала выполни вход.", parent=self)
            return
        if self.crl_dialog is not None and self.crl_dialog.winfo_exists():
            self.crl_dialog.lift()
            self.crl_dialog.focus_force()
            return
        self.crl_dialog = CrlDialog(
            self, self.state.get("crl", {}), self.refresh_crl_data,
        )

    def refresh_crl_data(self):
        if not self.auth or not self._ensure_auth_device():
            return
        settings, auth = self.settings_provider(), self.auth
        if self.crl_dialog is not None and self.crl_dialog.winfo_exists():
            self.crl_dialog.set_busy(True)

        def worker():
            admin_action(settings, auth, "crl_refresh")
            return load_admin_state(settings, auth)

        def success(state):
            self.state = state
            self.status.configure(text="CRL обновлён")
            self._fill()
            if self.crl_dialog is not None and self.crl_dialog.winfo_exists():
                self.crl_dialog.set_busy(False)
                self.crl_dialog.render(state.get("crl", {}))

        self._run_background(worker, success, "Обновление CRL")

    def _load(self, label=None):
        settings, auth = self.settings_provider(), self.auth

        def success(state):
            self.state = state
            self.status.configure(text=label or "Данные получены из Docker")
            self._fill()

        self._run_background(lambda: load_admin_state(settings, auth), success, "Управление")

    def _run_background(self, worker, success, error_title):
        if self._busy:
            self.status.configure(text="Предыдущая операция ещё выполняется")
            return
        self._busy = True
        self.status.configure(text="Выполняется…")

        def run():
            try:
                self._result_queue.put((True, worker(), success, error_title))
            except Exception as exc:
                self._result_queue.put((False, exc, success, error_title))

        threading.Thread(target=run, daemon=True).start()
        self.after(100, self._poll_result)

    def _poll_result(self):
        try:
            ok, value, success, error_title = self._result_queue.get_nowait()
        except queue.Empty:
            self.after(100, self._poll_result)
            return
        self._busy = False
        if ok:
            success(value)
        else:
            if self.crl_dialog is not None and self.crl_dialog.winfo_exists():
                self.crl_dialog.set_busy(False)
            self.status.configure(text="Операция не выполнена")
            messagebox.showerror(error_title, str(value), parent=self)

    def _fill(self):
        if self._inline_edit:
            self._cancel_inline_edit()
        for tree in (self.token_tree, self.system_tree, self.log_tree):
            tree.delete(*tree.get_children())
        tokens = self.state.get("tokens", [])
        pending = self.state.get("pending_tokens", [])
        for item in pending:
            self.token_tree.insert("", "end", iid=f"pending:{item['serial']}", values=(
                "Ожидает регистрации", "—", "—", "—",
                item["serial"], item.get("last_seen", "—")))
        for item in tokens:
            access = ", ".join(
                grant["target_name"] for grant in self.state.get("grants", [])
                if grant["token_serial"] == item["serial"]
            ) or "—"
            self.token_tree.insert("", "end", iid=f"token:{item['serial']}", values=(
                item["label"], item["role"], "Да" if item["enabled"] else "Нет",
                access, item["serial"], item.get("last_seen") or "—"))
        targets = self.state.get("targets", [])
        for item in targets:
            self.system_tree.insert("", "end", iid=f"target:{item['id']}", values=(
                item["name"], f"{item['internal_ip']}:{item['internal_port']}",
                item["gateway_port"], "Да" if item["enabled"] else "Нет"))
        self.port_min.set(str(self.state.get("port_min", ""))); self.port_max.set(str(self.state.get("port_max", "")))
        self.port_info.configure(text=f"Свободно: {self.state.get('free_ports', 0)} · активных RDP: {self.state.get('active_sessions', 0)}")
        for item in self.state.get("logs", []):
            self.log_tree.insert("", "end", values=(item.get("label") or item.get("token_serial"),
                item.get("name"), item.get("source_ip"), item.get("state"),
                item.get("started_at"), item.get("ended_at") or "—"))

    def _selected(self, tree, prefix, collection, key):
        selection = tree.selection()
        if not selection or not selection[0].startswith(prefix + ":"):
            return None
        value = selection[0].split(":", 1)[1]
        return next((item for item in collection if str(item[key]) == value), None)

    @staticmethod
    def _place_editor(tree, item_id, column, widget):
        bounds = tree.bbox(item_id, column)
        if not bounds:
            return False
        x, y, width, height = bounds
        widget.place(x=x + 1, y=y + 1, width=max(width - 2, 30), height=max(height - 2, 22))
        return True

    def _show_edit_controls(self, kind):
        if kind == "token":
            self.token_edit_hint.pack_forget()
            self.token_edit_cancel.pack(side="right")
            self.token_edit_ok.pack(side="right", padx=7)
        else:
            self.system_edit_hint.pack_forget()
            self.system_edit_cancel.pack(side="right")
            self.system_edit_ok.pack(side="right", padx=7)

    def _hide_edit_controls(self, kind):
        if kind == "token":
            self.token_edit_cancel.pack_forget()
            self.token_edit_ok.pack_forget()
            self.token_edit_hint.pack(side="right")
        else:
            self.system_edit_cancel.pack_forget()
            self.system_edit_ok.pack_forget()
            self.system_edit_hint.pack(side="right")

    def _cancel_inline_edit(self):
        if not self._inline_edit:
            return
        kind = self._inline_edit["kind"]
        for widget in self._inline_edit["widgets"]:
            widget.destroy()
        self._inline_edit = None
        self._hide_edit_controls(kind)

    def _tree_click(self, event):
        edit = self._inline_edit
        if not edit or event.widget is not edit["tree"]:
            return
        item_id = edit["tree"].identify_row(event.y)
        if item_id != edit["item_id"]:
            self.after_idle(self._commit_inline_edit)

    def _bind_inline_keys(self, widgets):
        for widget in widgets:
            widget.bind("<Return>", lambda _event: self._commit_inline_edit())
            widget.bind("<Escape>", lambda _event: self._cancel_inline_edit())

    def _begin_token_edit(self, event):
        item_id = self.token_tree.identify_row(event.y)
        if item_id.startswith("pending:"):
            serial = item_id.split(":", 1)[1]
            pending = next(
                (row for row in self.state.get("pending_tokens", []) if row["serial"] == serial),
                None,
            )
            if pending:
                self._complete_token_registration({
                    "action": "token_approve",
                    "serial": pending["serial"],
                    "default_label": "Новый токен",
                })
            return
        if not item_id.startswith("token:"):
            return
        if self._inline_edit:
            if self._inline_edit["item_id"] == item_id:
                return
            self._commit_inline_edit()
            return
        serial = item_id.split(":", 1)[1]
        item = next((row for row in self.state.get("tokens", []) if row["serial"] == serial), None)
        if item is None:
            return
        label_var = tk.StringVar(value=item["label"])
        role_var = tk.StringVar(value=item["role"])
        enabled_var = tk.StringVar(value="Да" if item["enabled"] else "Нет")
        current_access = {
            grant["target_id"] for grant in self.state.get("grants", [])
            if grant["token_serial"] == serial
        }
        access_vars = {
            target["id"]: tk.BooleanVar(value=target["id"] in current_access)
            for target in self.state.get("targets", [])
        }
        access_text = tk.StringVar()

        def update_access_text():
            names = [target["name"] for target in self.state.get("targets", [])
                     if access_vars[target["id"]].get()]
            access_text.set(", ".join(names) or "Нет доступа")

        label_entry = ttk.Entry(self.token_tree, textvariable=label_var)
        role_entry = ttk.Combobox(self.token_tree, textvariable=role_var,
                                  values=("USER", "ADMIN"), state="readonly")
        enabled_entry = ttk.Combobox(self.token_tree, textvariable=enabled_var,
                                     values=("Да", "Нет"), state="readonly")
        access_entry = ttk.Menubutton(self.token_tree, textvariable=access_text)
        access_menu = tk.Menu(access_entry, tearoff=False)
        for target in self.state.get("targets", []):
            access_menu.add_checkbutton(
                label=target["name"], variable=access_vars[target["id"]],
                command=update_access_text,
            )
        access_entry.configure(menu=access_menu)
        update_access_text()
        widgets = [label_entry, role_entry, enabled_entry, access_entry]
        for column, widget in zip(("#1", "#2", "#3", "#4"), widgets):
            self._place_editor(self.token_tree, item_id, column, widget)
        self._inline_edit = {
            "kind": "token", "tree": self.token_tree, "item_id": item_id,
            "serial": serial, "label": label_var, "role": role_var,
            "enabled": enabled_var, "access": access_vars, "widgets": widgets,
        }
        self._bind_inline_keys(widgets[:3])
        self._show_edit_controls("token")
        label_entry.focus_set()
        label_entry.selection_range(0, "end")

    def _begin_system_edit(self, event):
        item_id = self.system_tree.identify_row(event.y)
        if not item_id.startswith("target:"):
            return
        if self._inline_edit:
            if self._inline_edit["item_id"] == item_id:
                return
            self._commit_inline_edit()
            return
        target_id = int(item_id.split(":", 1)[1])
        item = next((row for row in self.state.get("targets", []) if row["id"] == target_id), None)
        if item is None:
            return
        variables = {
            "name": tk.StringVar(value=item["name"]),
            "internal": tk.StringVar(value=f"{item['internal_ip']}:{item['internal_port']}"),
            "gateway": tk.StringVar(value=str(item["gateway_port"])),
            "enabled": tk.StringVar(value="Да" if item["enabled"] else "Нет"),
        }
        widgets = [
            ttk.Entry(self.system_tree, textvariable=variables["name"]),
            ttk.Entry(self.system_tree, textvariable=variables["internal"]),
            ttk.Entry(self.system_tree, textvariable=variables["gateway"]),
            ttk.Combobox(self.system_tree, textvariable=variables["enabled"],
                         values=("Да", "Нет"), state="readonly"),
        ]
        for column, widget in zip(("#1", "#2", "#3", "#4"), widgets):
            self._place_editor(self.system_tree, item_id, column, widget)
        self._inline_edit = {
            "kind": "system", "tree": self.system_tree, "item_id": item_id,
            "target_id": target_id, "variables": variables, "widgets": widgets,
        }
        self._bind_inline_keys(widgets)
        self._show_edit_controls("system")
        widgets[0].focus_set()
        widgets[0].selection_range(0, "end")

    def _commit_inline_edit(self):
        edit = self._inline_edit
        if not edit:
            return
        if edit["kind"] == "token":
            label = edit["label"].get().strip()
            if not label:
                messagebox.showerror("Токен", "Название не может быть пустым.", parent=self)
                return
            values = {
                "serial": edit["serial"], "label": label, "role": edit["role"].get(),
                "enabled": edit["enabled"].get() == "Да",
                "target_ids": [target_id for target_id, selected in edit["access"].items()
                               if selected.get()],
            }
            self._cancel_inline_edit()
            self._action("token_update", **values)
            return
        variables = edit["variables"]
        try:
            internal_ip, internal_port = variables["internal"].get().strip().rsplit(":", 1)
            internal_port = int(internal_port)
            gateway_port = int(variables["gateway"].get())
        except ValueError:
            messagebox.showerror(
                "Система", "Внутренний адрес должен быть в виде IP:порт, порты — числа.", parent=self
            )
            return
        name = variables["name"].get().strip()
        if not name:
            messagebox.showerror("Система", "Название не может быть пустым.", parent=self)
            return
        values = {
            "target_id": edit["target_id"], "name": name,
            "internal_ip": internal_ip, "internal_port": internal_port,
            "gateway_port": gateway_port, "enabled": variables["enabled"].get() == "Да",
        }
        self._cancel_inline_edit()
        self._action("target_update", **values)

    def _action(self, action, **values):
        if not self.auth:
            messagebox.showerror("Управление", "Сначала выполни вход.", parent=self)
            return
        if not self._ensure_auth_device():
            return
        settings, auth = self.settings_provider(), self.auth

        def worker():
            admin_action(settings, auth, action, **values)
            return load_admin_state(settings, auth)

        def success(state):
            self.state = state
            self.status.configure(text="Изменение сохранено")
            self._fill()

        self._run_background(worker, success, "Управление")

    def _ensure_auth_device(self):
        fingerprint = self.auth.get("certificate_fingerprint") if self.auth else None
        if not fingerprint:
            return True
        present = any(
            obj.get("fingerprint") == fingerprint
            for token in self.inventory_provider()
            for obj in token.objects
        )
        if present:
            return True
        self.logout()
        messagebox.showerror(
            "Управление", "Административный токен извлечён. Выполнен выход.", parent=self
        )
        return False

    def import_token(self):
        if not self.auth:
            messagebox.showerror("Импорт токена", "Сначала выполни административный вход.", parent=self)
            return
        if not self._ensure_auth_device():
            return
        path = filedialog.askopenfilename(parent=self, title="Импорт карточки или сертификата",
            filetypes=(("Карточка или сертификат", "*.json *.pem *.cer *.crt *.der"), ("Все файлы", "*.*")))
        if not path:
            return
        try:
            record = load_file(path)
            existing = next((item for item in self.state.get("tokens", [])
                             if normalize_serial(item["serial"]) == normalize_serial(record["serial"])), None)
            if existing:
                messagebox.showinfo("Импорт токена", f"Сертификат уже зарегистрирован: {existing['label']}.\nЗапись и доступ не изменены.", parent=self)
                return
        except (OSError, ValueError, TypeError) as exc:
            messagebox.showerror("Импорт токена", str(exc), parent=self)
            return
        dialog = ImportTokenDialog(self, record)
        self.wait_window(dialog)
        if dialog.result:
            self._action("token_register", **dialog.result)

    def export_token(self):
        if not self.auth or not self._ensure_auth_device():
            messagebox.showerror("Экспорт токена", "Сначала выполни административный вход.", parent=self)
            return
        item = self._selected(self.token_tree, "token", self.state.get("tokens", []), "serial")
        if not item:
            messagebox.showinfo("Экспорт токена", "Выбери зарегистрированный токен в списке.", parent=self)
            return
        export_card(self, item)

    def approve_token(self):
        registered = {
            "".join(char for char in item["serial"].upper() if char.isalnum()).lstrip("0") or "0"
            for item in self.state.get("tokens", [])
        }
        candidates = []
        for token in self.inventory_provider():
            for certificate in token.objects:
                if not all(certificate.get(field) for field in
                           ("fingerprint", "serial", "subject", "issuer")):
                    continue
                normalized = "".join(
                    char for char in certificate["serial"].upper() if char.isalnum()
                ).lstrip("0") or "0"
                if normalized in registered:
                    continue
                token_name = token.label or token.model or token.vendor or token.reader
                candidates.append({
                    "action": "token_register",
                    "serial": certificate["serial"],
                    "subject": certificate["subject"],
                    "issuer": certificate["issuer"],
                    "default_label": token_name,
                    "display": f"{token_name} | {certificate['subject']} | {certificate['serial']}",
                })
        for pending in self.state.get("pending_tokens", []):
            normalized = "".join(
                char for char in pending["serial"].upper() if char.isalnum()
            ).lstrip("0") or "0"
            if normalized not in registered and not any(
                ("".join(char for char in item["serial"].upper() if char.isalnum()).lstrip("0") or "0") == normalized
                for item in candidates
            ):
                candidates.append({
                    "action": "token_approve",
                    "serial": pending["serial"],
                    "default_label": "Новый токен",
                    "display": f"Ожидает на сервере | {pending['subject']} | {pending['serial']}",
                })
        dialog = PhysicalTokenDialog(self, candidates)
        self.wait_window(dialog)
        selected = dialog.result
        if selected is None:
            return
        if selected.get("action") == "token_import_file":
            self.import_token()
            return
        self._complete_token_registration(selected)

    def _complete_token_registration(self, selected):
        selected = dict(selected)
        action = selected.pop("action")
        default_label = selected.pop("default_label")
        selected.pop("display", None)
        label = simpledialog.askstring(
            "Добавить токен", "Название:", initialvalue=default_label, parent=self
        )
        if label:
            selected.update(
                label=label,
                role="ADMIN" if messagebox.askyesno(
                    "Роль", "Сделать администратором?", parent=self
                ) else "USER",
            )
            self._action(action, **selected)

    def edit_token(self):
        item = self._selected(self.token_tree, "token", self.state.get("tokens", []), "serial")
        if not item: return
        label = simpledialog.askstring("Токен", "Название:", initialvalue=item["label"], parent=self)
        if label: self._action("token_update", serial=item["serial"], label=label,
            role="ADMIN" if messagebox.askyesno("Роль", "Администратор?", parent=self) else "USER",
            enabled=messagebox.askyesno("Состояние", "Токен активен?", parent=self))

    def delete_token(self):
        item = self._selected(self.token_tree, "token", self.state.get("tokens", []), "serial")
        if item and messagebox.askyesno("Удаление", f"Удалить токен {item['label']} и его привязки?", parent=self):
            self._action("token_delete", serial=item["serial"])

    def add_system(self):
        name = simpledialog.askstring("Система", "Название:", parent=self)
        ip = simpledialog.askstring("Система", "Внутренний IP:", parent=self) if name else None
        port = simpledialog.askinteger("Система", "RDP-порт:", initialvalue=3389, minvalue=1, maxvalue=65535, parent=self) if ip else None
        if name and ip and port: self._action("target_add", name=name, internal_ip=ip, internal_port=port)

    def edit_system(self):
        item = self._selected(self.system_tree, "target", self.state.get("targets", []), "id")
        if not item: return
        name = simpledialog.askstring("Система", "Название:", initialvalue=item["name"], parent=self)
        ip = simpledialog.askstring("Система", "Внутренний IP:", initialvalue=item["internal_ip"], parent=self) if name else None
        port = simpledialog.askinteger("Система", "RDP-порт:", initialvalue=item["internal_port"], minvalue=1, maxvalue=65535, parent=self) if ip else None
        gateway = simpledialog.askinteger("Система", "Порт шлюза:", initialvalue=item["gateway_port"], minvalue=1, maxvalue=65535, parent=self) if port else None
        if name and ip and port and gateway: self._action("target_update", target_id=item["id"], name=name, internal_ip=ip, internal_port=port, gateway_port=gateway)

    def delete_system(self):
        item = self._selected(self.system_tree, "target", self.state.get("targets", []), "id")
        if item and messagebox.askyesno("Удаление", f"Удалить систему {item['name']}?", parent=self): self._action("target_delete", target_id=item["id"])

    def change_grant(self, add):
        if not self.grant_token.get() or not self.grant_system.get(): return
        serial = self.grant_token.get().rsplit(" | ", 1)[1]
        target_id = int(self.grant_system.get().rsplit(" | ", 1)[1])
        self._action("grant_add" if add else "grant_delete", serial=serial, target_id=target_id)

    def save_ports(self):
        try: self._action("ports_update", port_min=int(self.port_min.get()), port_max=int(self.port_max.get()))
        except ValueError: messagebox.showerror("Порты", "Введи числа.", parent=self)
