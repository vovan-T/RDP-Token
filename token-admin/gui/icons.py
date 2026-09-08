import sys
import tkinter as tk
from tkinter import ttk
from pathlib import Path


ICON_NAMES = ("refresh", "settings", "info", "login", "logout", "emergency", "rename")


def resource_root():
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))


def load_icons(master):
    icon_dir = resource_root() / "assets" / "icons"
    return {
        name: tk.PhotoImage(master=master, file=str(icon_dir / f"{name}.png")).zoom(3, 3).subsample(4, 4)
        for name in ICON_NAMES
    }


class CenteredToplevel(tk.Toplevel):
    """A dialog that appears centered over its owning application window."""

    def __init__(self, parent=None, *args, **kwargs):
        super().__init__(parent, *args, **kwargs)
        self._dialog_parent = parent
        self.after_idle(self._place_over_parent)

    def _place_over_parent(self):
        try:
            if not self.winfo_exists():
                return
            self.update_idletasks()
            owner = self._dialog_parent.winfo_toplevel() if self._dialog_parent else None
            if owner is not None and owner.winfo_exists():
                owner.update_idletasks()
                owner_x, owner_y = owner.winfo_rootx(), owner.winfo_rooty()
                owner_width, owner_height = owner.winfo_width(), owner.winfo_height()
            else:
                owner_x = self.winfo_vrootx()
                owner_y = self.winfo_vrooty()
                owner_width = self.winfo_vrootwidth()
                owner_height = self.winfo_vrootheight()

            width = max(self.winfo_width(), self.winfo_reqwidth())
            height = max(self.winfo_height(), self.winfo_reqheight())
            x = owner_x + (owner_width - width) // 2
            y = owner_y + (owner_height - height) // 2

            screen_x, screen_y = self.winfo_vrootx(), self.winfo_vrooty()
            screen_right = screen_x + self.winfo_vrootwidth()
            screen_bottom = screen_y + self.winfo_vrootheight()
            x = max(screen_x, min(x, max(screen_x, screen_right - width)))
            y = max(screen_y, min(y, max(screen_y, screen_bottom - height)))
            self.geometry(f"+{x}+{y}")
        except tk.TclError:
            return


class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.window = None
        widget.bind("<Enter>", self._show, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _show(self, _event=None):
        if self.window or not self.text:
            return
        x = self.widget.winfo_rootx() + self.widget.winfo_width() // 2
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        self.window = tk.Toplevel(self.widget)
        self.window.wm_overrideredirect(True)
        self.window.wm_geometry(f"+{x}+{y}")
        tk.Label(
            self.window, text=self.text, background="#fff8d8", foreground="#1f2937",
            relief="solid", borderwidth=1, padx=7, pady=4, font=("Segoe UI", 9),
        ).pack()

    def _hide(self, _event=None):
        if self.window:
            self.window.destroy()
            self.window = None


def action_button(parent, text, command, **options):
    options.pop("width", None)
    options.pop("height", None)
    image = options.pop("image", None)
    font = options.pop("font", ("Segoe UI", 9))
    padx = options.pop("padx", 8)
    pady = options.pop("pady", 4)
    return tk.Button(
        parent,
        text=text,
        command=command,
        image=image,
        compound="left",
        relief="raised",
        borderwidth=2,
        background="SystemButtonFace",
        activebackground="SystemButtonFace",
        font=font,
        padx=padx,
        pady=pady,
        cursor="hand2",
        **options,
    )


def icon_button(parent, image, command, tooltip):
    button = tk.Button(
        parent,
        image=image,
        command=command,
        relief="raised",
        borderwidth=2,
        background="#d9d9d9",
        activebackground="#c8c8c8",
        cursor="hand2",
        width=38,
        height=34,
        padx=0,
        pady=0,
    )
    ToolTip(button, tooltip)
    return button
