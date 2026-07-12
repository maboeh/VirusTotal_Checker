from __future__ import annotations

import base64
import hashlib
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Callable

import requests

import config
from models.scan_result import ScanResult


class VirusTotalClient:
    def __init__(self, api_key: str | None = None) -> None:
        self._lock = threading.Lock()
        self._session = requests.Session()
        self.set_api_key(api_key)

    @property
    def is_configured(self) -> bool:
        return bool(self._api_key)

    def set_api_key(self, api_key: str | None = None) -> None:
        if api_key is not None:
            self._api_key = api_key.strip()
        else:
            self._api_key = config.VIRUSTOTAL_API_KEY
        self._session.headers.update({
            "x-apikey": self._api_key,
            "Accept": "application/json",
        })

    def scan_url(
        self,
        url: str,
        cancel_event: threading.Event | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> ScanResult:
        if not self.is_configured:
            return ScanResult.from_error("Kein API-Key konfiguriert. Bitte Einstellungen prüfen.")

        if not url or not url.strip():
            return ScanResult.from_error("Bitte eine gültige URL eingeben.")

        url = url.strip()
        validated = self._validate_url(url)
        if isinstance(validated, ScanResult):
            return validated
        url = validated

        if cancel_event and cancel_event.is_set():
            return ScanResult.from_error("Scan abgebrochen.")

        try:
            if on_progress:
                on_progress("URL wird auf bestehenden Bericht geprüft...")
            report = self._get_url_report(url, cancel_event)
            if report is not None:
                if on_progress:
                    on_progress("Bericht aus Cache geladen.")
                return report

            if cancel_event and cancel_event.is_set():
                return ScanResult.from_error("Scan abgebrochen.")

            if on_progress:
                on_progress("URL wird an VirusTotal gesendet...")

            with self._lock:
                response = self._request(
                    "post",
                    f"{config.VIRUSTOTAL_BASE_URL}/urls",
                    data={"url": url},
                    timeout=30,
                )
                response.raise_for_status()
                analysis_id = response.json()["data"]["id"]

            return self._poll_analysis(analysis_id, cancel_event, on_progress)

        except requests.exceptions.ConnectionError:
            return ScanResult.from_error("Verbindungsfehler. Bitte Internetverbindung prüfen.")
        except requests.exceptions.Timeout:
            return ScanResult.from_error("Zeitüberschreitung bei der Anfrage.")
        except requests.exceptions.HTTPError as e:
            return self._handle_http_error(e)
        except (KeyError, ValueError) as e:
            return ScanResult.from_error(f"Unerwartete API-Antwort: {e}")
        except requests.exceptions.RequestException as e:
            return ScanResult.from_error(str(e) or "Netzwerkfehler.")

    def _validate_url(self, url: str) -> str | ScanResult:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        if len(url) > config.MAX_URL_LENGTH:
            return ScanResult.from_error(
                f"URL zu lang. Maximum {config.MAX_URL_LENGTH} Zeichen."
            )
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return ScanResult.from_error("Bitte eine gültige URL mit Domain eingeben.")
        return url

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        max_redirects = 3
        redirect_count = 0
        while redirect_count <= max_redirects:
            response = self._session.request(method, url, allow_redirects=False, **kwargs)
            if response.is_redirect and response.headers.get("Location"):
                new_url = urllib.parse.urljoin(response.url, response.headers["Location"])
                parsed = urllib.parse.urlparse(new_url)
                if parsed.hostname and (parsed.hostname == "virustotal.com" or parsed.hostname.endswith(".virustotal.com")):
                    files = kwargs.get("files")
                    if files:
                        for v in files.values():
                            if isinstance(v, tuple):
                                f = v[1] if len(v) >= 2 else None
                            else:
                                f = v
                            if hasattr(f, "seek"):
                                f.seek(0)
                    url = new_url
                    redirect_count += 1
                    continue
                raise requests.exceptions.HTTPError(
                    f"Cross-origin redirect to {new_url} is not allowed",
                    response=response,
                )
            return response
        raise requests.exceptions.HTTPError(
            f"Too many redirects for {url}",
            response=response,
        )

    def _get_url_report(
        self, url: str, cancel_event: threading.Event | None
    ) -> ScanResult | None:
        if cancel_event and cancel_event.is_set():
            return ScanResult.from_error("Scan abgebrochen.")

        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        try:
            with self._lock:
                response = self._request(
                    "get",
                    f"{config.VIRUSTOTAL_BASE_URL}/urls/{url_id}",
                    timeout=30,
                )
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return ScanResult.from_report(response.json())
        except requests.exceptions.ConnectionError:
            return ScanResult.from_error("Verbindungsfehler. Bitte Internetverbindung prüfen.")
        except requests.exceptions.Timeout:
            return ScanResult.from_error("Zeitüberschreitung bei der Anfrage.")
        except requests.exceptions.HTTPError as e:
            return self._handle_http_error(e)
        except (KeyError, ValueError) as e:
            return ScanResult.from_error(f"Unerwartete API-Antwort: {e}")
        except requests.exceptions.RequestException as e:
            return ScanResult.from_error(str(e) or "Netzwerkfehler.")

    def scan_file(
        self,
        file_path: str,
        cancel_event: threading.Event | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> ScanResult:
        if not self.is_configured:
            return ScanResult.from_error("Kein API-Key konfiguriert. Bitte Einstellungen prüfen.")

        path = Path(file_path)
        if not path.is_file():
            return ScanResult.from_error(f"Bitte eine gültige Datei auswählen: {path}")

        try:
            max_size = config.MAX_FILE_SIZE_MB * 1024 * 1024
            if path.stat().st_size > max_size:
                return ScanResult.from_error(
                    f"Datei zu groß. Maximal {config.MAX_FILE_SIZE_MB} MB erlaubt."
                )

            if cancel_event and cancel_event.is_set():
                return ScanResult.from_error("Scan abgebrochen.")

            file_hash = self._hash_file(path, cancel_event, on_progress)
            if isinstance(file_hash, ScanResult):
                return file_hash

            if on_progress:
                on_progress("Datei wird auf bestehenden Bericht geprüft...")
            report = self._get_file_report(file_hash, cancel_event)
            if report is not None:
                if on_progress:
                    on_progress("Bericht aus Cache geladen.")
                return report

            if cancel_event and cancel_event.is_set():
                return ScanResult.from_error("Scan abgebrochen.")

            if on_progress:
                on_progress(f"Datei wird hochgeladen: {path.name}...")

            with open(path, "rb") as f:
                with self._lock:
                    response = self._request(
                        "post",
                        f"{config.VIRUSTOTAL_BASE_URL}/files",
                        files={"file": (path.name, f)},
                        timeout=120,
                    )
                response.raise_for_status()
                analysis_id = response.json()["data"]["id"]

            return self._poll_analysis(analysis_id, cancel_event, on_progress)

        except requests.exceptions.ConnectionError:
            return ScanResult.from_error("Verbindungsfehler. Bitte Internetverbindung prüfen.")
        except requests.exceptions.Timeout:
            return ScanResult.from_error("Zeitüberschreitung beim Hochladen.")
        except requests.exceptions.HTTPError as e:
            return self._handle_http_error(e)
        except (KeyError, ValueError) as e:
            return ScanResult.from_error(f"Unerwartete API-Antwort: {e}")
        except OSError as e:
            return ScanResult.from_error(f"Dateifehler: {e}")
        except requests.exceptions.RequestException as e:
            return ScanResult.from_error(str(e) or "Netzwerkfehler.")

    def _hash_file(
        self,
        path: Path,
        cancel_event: threading.Event | None,
        on_progress: Callable[[str], None] | None,
    ) -> str | ScanResult:
        if on_progress:
            on_progress("SHA-256 der Datei wird berechnet...")
        hasher = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while True:
                    if cancel_event and cancel_event.is_set():
                        return ScanResult.from_error("Scan abgebrochen.")
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    hasher.update(chunk)
            return hasher.hexdigest()
        except OSError as e:
            return ScanResult.from_error(f"Dateifehler: {e}")

    def _get_file_report(
        self, file_hash: str, cancel_event: threading.Event | None
    ) -> ScanResult | None:
        if cancel_event and cancel_event.is_set():
            return ScanResult.from_error("Scan abgebrochen.")

        try:
            with self._lock:
                response = self._request(
                    "get",
                    f"{config.VIRUSTOTAL_BASE_URL}/files/{file_hash}",
                    timeout=30,
                )
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return ScanResult.from_report(response.json())
        except requests.exceptions.ConnectionError:
            return ScanResult.from_error("Verbindungsfehler. Bitte Internetverbindung prüfen.")
        except requests.exceptions.Timeout:
            return ScanResult.from_error("Zeitüberschreitung bei der Anfrage.")
        except requests.exceptions.HTTPError as e:
            return self._handle_http_error(e)
        except (KeyError, ValueError) as e:
            return ScanResult.from_error(f"Unerwartete API-Antwort: {e}")
        except requests.exceptions.RequestException as e:
            return ScanResult.from_error(str(e) or "Netzwerkfehler.")

    def _poll_analysis(
        self,
        analysis_id: str,
        cancel_event: threading.Event | None = None,
        on_progress: Callable[[str], None] | None = None,
    ) -> ScanResult:
        consecutive_5xx = 0
        for attempt in range(1, config.POLL_MAX_ATTEMPTS + 1):
            if cancel_event and cancel_event.is_set():
                return ScanResult.from_error("Scan abgebrochen.")

            if on_progress:
                on_progress(f"Analyse läuft... ({attempt}/{config.POLL_MAX_ATTEMPTS})")

            sleep_time = min(
                config.POLL_INTERVAL_SECONDS * (2 ** (attempt - 1)),
                config.POLL_MAX_INTERVAL_SECONDS,
            )
            try:
                with self._lock:
                    response = self._request(
                        "get",
                        f"{config.VIRUSTOTAL_BASE_URL}/analyses/{analysis_id}",
                        timeout=30,
                    )
                response.raise_for_status()
                data = response.json()
                status = data.get("data", {}).get("attributes", {}).get("status")
                if status == "completed":
                    if on_progress:
                        on_progress("Analyse abgeschlossen!")
                    return ScanResult.from_api_response(data)
                consecutive_5xx = 0
            except requests.exceptions.HTTPError as e:
                if e.response is not None:
                    status_code = e.response.status_code
                    if status_code == 429:
                        retry_after = e.response.headers.get("Retry-After")
                        try:
                            retry_seconds = int(retry_after) if retry_after else None
                        except (TypeError, ValueError):
                            retry_seconds = None
                        base_sleep = min(
                            config.POLL_INTERVAL_SECONDS * (2 ** (attempt - 1)),
                            config.POLL_MAX_INTERVAL_SECONDS,
                        )
                        sleep_time = max(retry_seconds or 0, base_sleep)
                        sleep_time = min(sleep_time, 60)
                        if on_progress:
                            on_progress(f"Rate-Limit erreicht, warte {sleep_time}s...")
                    elif 400 <= status_code < 500:
                        return self._handle_http_error(e)
                    elif 500 <= status_code < 600:
                        consecutive_5xx += 1
                        if consecutive_5xx >= 3:
                            return ScanResult.from_error(
                                f"Server-Fehler {status_code} persistiert. Analyse abgebrochen."
                            )
                        if on_progress:
                            on_progress(f"Server-Fehler {status_code}, retry...")
                    else:
                        sleep_time = min(
                            config.POLL_INTERVAL_SECONDS * (2 ** (attempt - 1)),
                            config.POLL_MAX_INTERVAL_SECONDS,
                        )
            except requests.exceptions.RequestException:
                pass
            except (ValueError, AttributeError):
                pass

            if attempt < config.POLL_MAX_ATTEMPTS:
                if cancel_event:
                    if cancel_event.wait(sleep_time):
                        return ScanResult.from_error("Scan abgebrochen.")
                else:
                    time.sleep(sleep_time)

        return ScanResult.from_error(
            "Zeitüberschreitung: Analyse konnte nicht abgeschlossen werden."
        )

    @staticmethod
    def _handle_http_error(error: requests.exceptions.HTTPError) -> ScanResult:
        status_code = error.response.status_code if error.response is not None else 0
        messages = {
            401: "Ungültiger API-Key. Bitte Einstellungen prüfen.",
            403: "Zugriff verweigert. API-Key hat nicht die nötigen Berechtigungen.",
            429: "Rate-Limit erreicht. Bitte warte und versuche es erneut.",
            404: "Ressource nicht gefunden.",
        }
        message = messages.get(status_code, f"HTTP-Fehler {status_code}: {error}")
        return ScanResult.from_error(message)
