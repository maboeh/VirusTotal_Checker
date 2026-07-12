from __future__ import annotations

import threading
import webbrowser
from typing import Callable

import customtkinter as ctk

from api.update_checker import UpdateInfo
from config import APP_NAME, VERSION
from ui.macos_utils import bring_to_front


class UpdateDialog(ctk.CTkToplevel):
    def __init__(
        self,
        master: ctk.CTk,
        update_info: UpdateInfo,
        *,
        on_install: Callable[[UpdateInfo], None] | None = None,
    ) -> None:
        super().__init__(master)
        self.title("Update verfügbar")
        self.geometry("440x280")
        self.resizable(False, False)
        self.transient(master)
        self._update_info = update_info
        self._on_install = on_install
        self._build_ui()
        self._center()
        # WICHTIG: Auf macOS darf grab_set() erst laufen, wenn das Fenster
        # sichtbar und fokussiert ist, sonst blockiert es den Main-Loop.
        self._make_modal()

    def _make_modal(self) -> None:
        # Auf macOS erscheint das Toplevel sonst hinter dem Hauptfenster;
        # grab_set() wuerde dann alle Eingaben an ein unsichtbares Fenster
        # binden und die App wirkt eingefroren. Daher zuerst nach vorne
        # heben und fokussieren, bevor der grab gesetzt wird.
        self.update_idletasks()
        bring_to_front(self)
        self.focus_set()
        self.grab_set()

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)

        header = ctk.CTkLabel(
            self,
            text="Update verfügbar",
            font=ctk.CTkFont(size=18, weight="bold"),
        )
        header.grid(row=0, column=0, padx=20, pady=(20, 5), sticky="w")

        info_text = (
            f"Es ist eine neue Version von {APP_NAME} verfügbar.\n\n"
            f"Aktuelle Version: {VERSION}\n"
            f"Neue Version:     {self._update_info.latest_version}"
        )
        info_label = ctk.CTkLabel(self, text=info_text, justify="left")
        info_label.grid(row=1, column=0, padx=20, pady=5, sticky="w")

        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.grid(row=2, column=0, padx=20, pady=(15, 20), sticky="ew")
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)
        button_frame.grid_columnconfigure(2, weight=1)

        self._install_button = ctk.CTkButton(
            button_frame,
            text="Installieren & Neustart",
            command=self._on_install_clicked,
        )
        self._install_button.grid(row=0, column=0, sticky="w")

        self._release_button = ctk.CTkButton(
            button_frame,
            text="Release-Notes",
            command=self._open_release_notes,
        )
        self._release_button.grid(row=0, column=1)

        self._later_button = ctk.CTkButton(
            button_frame,
            text="Später",
            command=self.destroy,
        )
        self._later_button.grid(row=0, column=2, sticky="e")

    def _on_install_clicked(self) -> None:
        if self._on_install:
            self._on_install(self._update_info)
        self.destroy()

    def _open_release_notes(self) -> None:
        if self._update_info.release_url:
            webbrowser.open(self._update_info.release_url)

    def _center(self) -> None:
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
