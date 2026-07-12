from __future__ import annotations

from typing import Callable

import customtkinter as ctk

from config import VIRUSTOTAL_API_KEY, save_api_key


class SettingsDialog(ctk.CTkToplevel):
    def __init__(self, master: ctk.CTk, *, on_save: Callable[[str], None] | None = None) -> None:
        super().__init__(master)
        self.title("Einstellungen")
        self.geometry("400x220")
        self.resizable(False, False)
        self.transient(master)
        self._on_save = on_save
        self._build_ui()
        self._center()
        # Reihenfolge auf macOS kritisch: erst Fenster sichtbar machen,
        # dann grab setzen, sonst freeze des Main-Loops.
        self.after(50, self._make_modal)

    def _make_modal(self) -> None:
        self.focus_set()
        self.grab_set()

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)

        label = ctk.CTkLabel(
            self, text="VirusTotal API-Key", font=ctk.CTkFont(size=14, weight="bold")
        )
        label.grid(row=0, column=0, padx=20, pady=(20, 5), sticky="w")

        self._entry = ctk.CTkEntry(self, show="*", width=360)
        self._entry.insert(0, VIRUSTOTAL_API_KEY)
        self._entry.grid(row=1, column=0, padx=20, pady=5, sticky="ew")

        self._show_button = ctk.CTkButton(
            self, text="Anzeigen", width=80, command=self._toggle_visibility
        )
        self._show_button.grid(row=2, column=0, padx=20, pady=(0, 10), sticky="e")

        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.grid(row=3, column=0, padx=20, pady=(10, 20), sticky="ew")
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)

        self._save_button = ctk.CTkButton(
            button_frame, text="Speichern", command=self._save
        )
        self._save_button.grid(row=0, column=0, sticky="w")

        self._cancel_button = ctk.CTkButton(
            button_frame, text="Abbrechen", command=self.destroy
        )
        self._cancel_button.grid(row=0, column=1, sticky="e")

    def _toggle_visibility(self) -> None:
        if self._entry.cget("show") == "*":
            self._entry.configure(show="")
            self._show_button.configure(text="Verbergen")
        else:
            self._entry.configure(show="*")
            self._show_button.configure(text="Anzeigen")

    def _save(self) -> None:
        key = self._entry.get().strip()
        save_api_key(key)
        if self._on_save:
            self._on_save(key)
        self.destroy()

    def _center(self) -> None:
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
