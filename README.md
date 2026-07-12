# VirusTotal Checker

Desktop-Anwendung zum Scannen von URLs und Dateien über die VirusTotal API v3.

## Voraussetzungen

- Python 3.10+
- VirusTotal API-Key ([kostenlos registrieren](https://www.virustotal.com/gui/join-us))

## Installation

```bash
# Repository klonen
git clone <repo-url>
cd VirusTotal_Checker

# Virtuelle Umgebung erstellen & aktivieren
python -m venv .venv
source .venv/bin/activate  # macOS/Linux
# .venv\Scripts\activate   # Windows

# Abhängigkeiten installieren
pip install -r requirements.txt
```

## Konfiguration

Starte die App und klicke auf **Einstellungen**, um den VirusTotal API-Key zu hinterlegen.
Alternativ kannst du die Umgebungsvariable `VIRUSTOTAL_API_KEY` setzen oder eine `.env`-Datei im Projektverzeichnis verwenden.

**Wichtig:** Der API-Key wird nicht in das PyInstaller-Bundle integriert. Für den Build ist daher zwingend die Eingabe über den Einstellungsdialog nötig.

## Starten

```bash
python main.py
```

## Funktionen

- **URL-Scan** – Überprüfe beliebige URLs auf Bedrohungen
- **Datei-Scan** – Lade Dateien hoch und lasse sie von 70+ Scannern analysieren
- **Vorab-Prüfung** – Vor einem Upload wird per SHA-256 (Dateien) bzw. URL-Hash (URLs) geprüft, ob ein Bericht bereits existiert
- **Cancel-Button** – Laufende Scans können abgebrochen werden
- **Farbodierte Ergebnisse** – Sofort erkennen, welche Scanner Bedrohungen melden
- **Einstellungsdialog** – API-Key bequem in der App hinterlegen

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

## Build (optional)

```bash
pip install pyinstaller
pyinstaller build.spec
```

Nach dem Build findest du die App ohne gebundelte `.env` unter `dist/virustotal_scanner`.

## Lizenz

MIT
