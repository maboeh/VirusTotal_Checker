from __future__ import annotations

import threading

import customtkinter as ctk

from api.virustotal_client import VirusTotalClient
from models.scan_result import ScanResult


class URLScanFrame(ctk.CTkFrame):
    def __init__(self, master: ctk.CTkBaseClass, client: VirusTotalClient) -> None:
        super().__init__(master)
        self._client = client
        self._scanning = False
        self._cancel_event: threading.Event | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        self.grid_columnconfigure(0, weight=1)

        input_frame = ctk.CTkFrame(self, fg_color="transparent")
        input_frame.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="ew")
        input_frame.grid_columnconfigure(0, weight=1)

        self._url_label = ctk.CTkLabel(
            input_frame, text="URL eingeben:", anchor="w", font=ctk.CTkFont(size=14)
        )
        self._url_label.grid(row=0, column=0, sticky="w", pady=(0, 5))

        entry_row = ctk.CTkFrame(input_frame, fg_color="transparent")
        entry_row.grid(row=1, column=0, sticky="ew")
        entry_row.grid_columnconfigure(0, weight=1)

        self._url_entry = ctk.CTkEntry(
            entry_row, placeholder_text="https://example.com", height=40
        )
        self._url_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self._url_entry.bind("<Return>", lambda _: self._start_scan())

        self._scan_button = ctk.CTkButton(
            entry_row, text="Scannen", command=self._start_scan, width=120, height=40
        )
        self._scan_button.grid(row=0, column=1)

        self._cancel_button = ctk.CTkButton(
            entry_row,
            text="Abbrechen",
            command=self._cancel_scan,
            width=120,
            height=40,
        )
        self._cancel_button.grid(row=0, column=1)
        self._cancel_button.grid_remove()

        self._status_label = ctk.CTkLabel(
            self, text="", anchor="w", font=ctk.CTkFont(size=12)
        )
        self._status_label.grid(row=1, column=0, padx=20, pady=(0, 5), sticky="w")

        self._progress_bar = ctk.CTkProgressBar(self)
        self._progress_bar.grid(row=2, column=0, padx=20, sticky="ew")
        self._progress_bar.set(0)
        self._progress_bar.grid_remove()

        self._summary_label = ctk.CTkLabel(
            self, text="", anchor="w", font=ctk.CTkFont(size=14, weight="bold")
        )
        self._summary_label.grid(row=3, column=0, padx=20, pady=(10, 5), sticky="w")

        self._result_textbox = ctk.CTkTextbox(
            self,
            wrap="word",
            state="disabled",
            font=ctk.CTkFont(size=13),
            height=200,
        )
        self._result_textbox.grid(row=4, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self._result_textbox.tag_config("malicious", foreground="#e74c3c")
        self._result_textbox.tag_config("safe", foreground="#2ecc71")
        self.grid_rowconfigure(4, weight=1)

    def _start_scan(self) -> None:
        if self._scanning:
            return
        url = self._url_entry.get().strip()
        if not url:
            self._summary_label.configure(
                text="Bitte eine URL eingeben.", text_color="#e74c3c"
            )
            return
        self._scanning = True
        self._scan_button.grid_remove()
        self._cancel_button.grid()
        self._url_entry.configure(state="disabled")
        self._clear_results()
        self._progress_bar.grid()
        self._progress_bar.configure(mode="indeterminate")
        self._progress_bar.start()

        self._cancel_event = threading.Event()
        thread = threading.Thread(
            target=self._run_scan,
            args=(url, self._cancel_event),
            daemon=True,
        )
        thread.start()

    def _run_scan(self, url: str, cancel_event: threading.Event) -> None:
        result = self._client.scan_url(
            url, cancel_event=cancel_event, on_progress=self._on_progress
        )
        self.after(0, lambda: self._display_result(result))

    def _cancel_scan(self) -> None:
        if self._cancel_event:
            self._cancel_event.set()
        self._cancel_button.configure(state="disabled")

    def _on_progress(self, message: str) -> None:
        self.after(0, lambda: self._status_label.configure(text=message))

    def _display_result(self, result: ScanResult) -> None:
        self._progress_bar.stop()
        self._progress_bar.grid_remove()
        self._scanning = False
        self._url_entry.configure(state="normal")
        self._cancel_button.grid_remove()
        self._scan_button.grid()
        self._cancel_button.configure(state="normal")

        if result.error:
            self._status_label.configure(text="")
            self._summary_label.configure(text=result.error, text_color="#e74c3c")
            return

        self._status_label.configure(text="")

        total = result.total_scanners
        malicious = result.malicious_count
        if malicious > 0:
            self._summary_label.configure(
                text=f"WARNUNG - {malicious}/{total} Scanner melden Bedrohungen",
                text_color="#e74c3c",
            )
        else:
            self._summary_label.configure(
                text=f"OK - Keine Bedrohungen erkannt ({total} Scanner)",
                text_color="#2ecc71",
            )

        self._result_textbox.configure(state="normal")
        self._result_textbox.delete("1.0", "end")
        for verdict in result.verdicts:
            self._add_verdict_line(verdict)
        self._result_textbox.configure(state="disabled")

    def _add_verdict_line(self, verdict) -> None:
        result_text = verdict.result if verdict.result else verdict.category
        line = f"{verdict.scanner_name}: {result_text}\n"
        tag = "malicious" if verdict.is_malicious else "safe"
        self._result_textbox.insert("end", line, tag)

    def _clear_results(self) -> None:
        self._result_textbox.configure(state="normal")
        self._result_textbox.delete("1.0", "end")
        self._result_textbox.configure(state="disabled")
        self._summary_label.configure(text="")
        self._status_label.configure(text="")
