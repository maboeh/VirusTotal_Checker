from __future__ import annotations

import customtkinter as ctk

from api.virustotal_client import VirusTotalClient
from config import VIRUSTOTAL_API_KEY
from ui.file_scan_frame import FileScanFrame
from ui.settings_dialog import SettingsDialog
from ui.url_scan_frame import URLScanFrame


class App(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()

        self.title("VirusTotal Scanner")
        self.geometry("800x700")
        self.minsize(600, 500)

        ctk.set_appearance_mode("system")
        ctk.set_default_color_theme("blue")

        self._client = VirusTotalClient()
        self._build_ui()
        self._center_window()

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        header_frame.grid_columnconfigure(0, weight=1)

        header = ctk.CTkLabel(
            header_frame,
            text="VirusTotal Scanner",
            font=ctk.CTkFont(size=24, weight="bold"),
        )
        header.grid(row=0, column=0, sticky="w")

        self._settings_button = ctk.CTkButton(
            header_frame,
            text="Einstellungen",
            command=self._open_settings,
            width=120,
        )
        self._settings_button.grid(row=0, column=1, sticky="e")

        self._warning = ctk.CTkLabel(
            self,
            text="Kein API-Key konfiguriert! Bitte Einstellungen öffnen.",
            text_color="#e74c3c",
            font=ctk.CTkFont(size=13),
        )
        self._warning.grid(row=1, column=0, padx=20, sticky="w")
        if self._client.is_configured:
            self._warning.grid_remove()

        self._tabview = ctk.CTkTabview(self)
        self._tabview.grid(row=2, column=0, padx=20, pady=(10, 20), sticky="nsew")

        url_tab = self._tabview.add("URL-Scan")
        url_tab.grid_columnconfigure(0, weight=1)
        url_tab.grid_rowconfigure(0, weight=1)
        self._url_frame = URLScanFrame(url_tab, self._client)
        self._url_frame.grid(row=0, column=0, sticky="nsew")

        file_tab = self._tabview.add("Datei-Scan")
        file_tab.grid_columnconfigure(0, weight=1)
        file_tab.grid_rowconfigure(0, weight=1)
        self._file_frame = FileScanFrame(file_tab, self._client)
        self._file_frame.grid(row=0, column=0, sticky="nsew")

        footer = ctk.CTkLabel(
            self,
            text="Powered by VirusTotal API v3",
            font=ctk.CTkFont(size=11),
            text_color="gray",
        )
        footer.grid(row=3, column=0, pady=(0, 10))

    def _open_settings(self) -> None:
        if hasattr(self, "_settings_dialog") and self._settings_dialog.winfo_exists():
            self._settings_dialog.focus_set()
            return
        self._settings_dialog = SettingsDialog(self, on_save=self._on_api_key_changed)

    def _on_api_key_changed(self, api_key: str) -> None:
        self._client.set_api_key(api_key)
        if self._client.is_configured:
            self._warning.grid_remove()
        else:
            self._warning.grid()

    def _center_window(self) -> None:
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")
