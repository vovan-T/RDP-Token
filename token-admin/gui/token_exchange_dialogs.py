from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core.token_exchange import export_bytes, registration_record, suggested_filename
from gui.icons import CenteredToplevel, action_button


def export_card(parent, source, label=None):
    try:
        record = registration_record(source, label)
        data = export_bytes(record)
    except (ValueError, TypeError) as exc:
        messagebox.showerror("Экспорт токена", str(exc), parent=parent)
        return
    path = filedialog.asksaveasfilename(parent=parent, title="Экспорт карточки токена",
        defaultextension=".rdptoken.json", initialfile=suggested_filename(record),
        filetypes=(("Карточка токена", "*.rdptoken.json"), ("JSON", "*.json")))
    if not path:
        return
    try:
        Path(path).write_bytes(data)
    except OSError as exc:
        messagebox.showerror("Экспорт токена", str(exc), parent=parent)
        return
    detail = "Публичный сертификат включён." if record["certificate_present"] else "Сохранены регистрационные данные; самого сертификата в карточке нет."
    messagebox.showinfo("Экспорт токена", f"Карточка сохранена.\n{detail}\nЗакрытые ключи, PIN, роли и доступ не экспортируются.", parent=parent)


class ImportTokenDialog(CenteredToplevel):
    def __init__(self, parent, record):
        super().__init__(parent)
        self.title("Импорт токена — проверка данных")
        self.transient(parent)
        self.grab_set()
        self.result = None
        self.record = record
        self.minsize(600, 350)
        body = ttk.Frame(self, padding=16)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Название:").pack(anchor="w")
        self.label = tk.StringVar(value=record["label"])
        ttk.Entry(body, textvariable=self.label, width=72).pack(fill="x", pady=(3, 10))
        details = tk.Text(body, height=9, width=78, wrap="word")
        details.pack(fill="both", expand=True)
        details.insert("1.0", "\n".join(f"{title}: {record.get(name) or '—'}" for name, title in (
            ("serial", "Серийный номер сертификата (HEX)"), ("subject", "Subject"),
            ("issuer", "Issuer"), ("fingerprint_sha256", "SHA-256"),
            ("not_after_date", "Действителен до"))))
        details.configure(state="disabled")
        warning = ("Карточка содержит публичный сертификат. Доверие и CRL проверяются сервером при входе."
                   if record["certificate_present"] else
                   "Только регистрационные данные, без сертификата. Сверь их с владельцем по другому каналу.")
        if record.get("date_warning"):
            warning += "\nСертификат ещё не действует или уже просрочен — вход с ним не пройдёт."
        ttk.Label(body, text=warning, wraplength=610).pack(anchor="w", pady=10)
        ttk.Label(body, text="Будет создан USER без назначенных систем. Роль и доступ меняются отдельно.",
                  wraplength=610).pack(anchor="w")
        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(14, 0))
        action_button(buttons, "Отмена", self.destroy).pack(side="right")
        action_button(buttons, "Добавить", self._accept).pack(side="right", padx=7)

    def _accept(self):
        try:
            record = registration_record(self.record, self.label.get())
        except ValueError as exc:
            messagebox.showerror("Импорт токена", str(exc), parent=self)
            return
        self.result = {name: record[name] for name in ("serial", "subject", "issuer", "label")}
        self.result["role"] = "USER"
        self.destroy()
