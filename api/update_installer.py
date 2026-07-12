from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

import requests

from api.update_checker import UpdateInfo


def _download_archive(url: str, dest: Path, timeout: float = 60.0) -> None:
    response = requests.get(url, stream=True, timeout=timeout)
    response.raise_for_status()
    with dest.open("wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)


def _app_root() -> Path:
    """
    Liefert das Verzeichnis, das die laufende Anwendung enthält.

    Bei einem PyInstaller-Build ist das der Ordner mit dem Executable
    (bzw. bei .app der Contents/MacOS-Ordner). Im Dev-Modus ist es
    das Projektverzeichnis.
    """
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def _extract_archive(archive_path: Path, dest_dir: Path) -> None:
    if archive_path.suffix == ".zip":
        with zipfile.ZipFile(archive_path) as zf:
            zf.extractall(dest_dir)
    elif archive_path.suffix == ".gz":
        shutil.unpack_archive(archive_path, dest_dir, format="gztar")
    else:
        shutil.unpack_archive(archive_path, dest_dir)


def _find_new_app(extracted_dir: Path) -> Path | None:
    """Findet die neue .app bzw. den neuen Ordner nach dem Entpacken."""
    system = platform.system()
    if system == "Darwin":
        for p in extracted_dir.rglob("*.app"):
            return p
        return None
    # Windows/Linux: suche den virustotal_scanner-Ordner
    candidate = extracted_dir / "virustotal_scanner"
    if candidate.is_dir():
        return candidate
    for p in extracted_dir.iterdir():
        if p.is_dir():
            return p
    return None


def _replace_and_restart_macos(new_app: Path) -> None:
    """
    Ersetzt die alte .app durch die neue und startet sie neu.

    Da die laufende .app nicht überschrieben werden kann, während sie
    läuft, wird ein Shell-Skript geschrieben, das nach kurzer Pause
    die alte App löscht, die neue an deren Stelle verschiebt und
    sie dann startet.
    """
    current_app = Path(sys.executable).resolve()
    # sys.executable ist .../VirusTotal Scanner.app/Contents/MacOS/virustotal_scanner
    while current_app.name != "VirusTotal Scanner.app" and current_app.parent != current_app:
        current_app = current_app.parent
    if current_app.name != "VirusTotal Scanner.app":
        raise RuntimeError("Konnte aktuelle .app nicht ermitteln")

    target_location = current_app.parent / "VirusTotal Scanner.app"
    script = f"""#!/bin/bash
sleep 2
rm -rf "{target_location}"
mv "{new_app}" "{target_location}"
open "{target_location}"
"""
    script_path = Path(tempfile.gettempdir()) / "vt_update.sh"
    script_path.write_text(script)
    os.chmod(script_path, 0o755)
    subprocess.Popen(["/bin/bash", str(script_path)], start_new_session=True)


def _replace_and_restart_windows_linux(new_dir: Path) -> None:
    """
    Ersetzt den alten virustotal_scanner-Ordner und startet das
    Executable neu. Ein Shell-Skript wartet, bis die alte App beendet
    ist, kopiert dann die neuen Dateien und startet sie.
    """
    current_dir = _app_root()
    exe_name = "virustotal_scanner.exe" if platform.system() == "Windows" else "virustotal_scanner"
    current_exe = current_dir / exe_name

    if platform.system() == "Windows":
        script = f"""@echo off
timeout /t 2 /nobreak >nul
xcopy /e /y /i "{new_dir}" "{current_dir}"
start "" "{current_exe}"
"""
        script_path = Path(tempfile.gettempdir()) / "vt_update.bat"
        script_path.write_text(script)
        subprocess.Popen(["cmd", "/c", str(script_path)], creationflags=subprocess.DETACHED_PROCESS)
    else:
        script = f"""#!/bin/bash
sleep 2
cp -rf "{new_dir}/"* "{current_dir}/"
"{current_exe}" &
"""
        script_path = Path(tempfile.gettempdir()) / "vt_update.sh"
        script_path.write_text(script)
        os.chmod(script_path, 0o755)
        subprocess.Popen(["/bin/bash", str(script_path)], start_new_session=True)


def perform_update(update_info: UpdateInfo) -> None:
    """
    Lädt das Plattform-Archiv herunter, entpackt es und leitet
    das Ersetzen + Neustarten ein. Die aufrufende App muss sich
    danach selbst beenden.
    """
    if not update_info.download_url:
        raise RuntimeError("Kein Download-URL für diese Plattform verfügbar")

    tmp_dir = Path(tempfile.mkdtemp(prefix="vt_update_"))
    archive_path = tmp_dir / "download.zip"

    _download_archive(update_info.download_url, archive_path)
    _extract_archive(archive_path, tmp_dir / "extracted")
    new_app = _find_new_app(tmp_dir / "extracted")
    if new_app is None:
        raise RuntimeError("Konnte neue Anwendung im Archiv nicht finden")

    if platform.system() == "Darwin":
        _replace_and_restart_macos(new_app)
    else:
        _replace_and_restart_windows_linux(new_app)

    # Aufrufer muss sich danach beenden
