# VirusTotal Checker

A simple desktop application for scanning URLs and files using the VirusTotal API v3.

## Requirements

- Python 3.10+
- A VirusTotal API key ([sign up for free](https://www.virustotal.com/gui/join-us))

## Installation

```bash
# Clone the repository
git clone https://github.com/maboeh/VirusTotal_Checker.git
cd VirusTotal_Checker

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # macOS/Linux
# .venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
```

## Configuration

Start the app and click **Settings** to enter your VirusTotal API key.
Alternatively, you can set the `VIRUSTOTAL_API_KEY` environment variable or create a `.env` file in the project root.

**Important:** The API key is not bundled into the PyInstaller build. For a build, you must enter the key through the settings dialog.

## Usage

```bash
python main.py
```

## Features

- **URL Scan** – Check any URL for threats
- **File Scan** – Upload files and have them analyzed by 70+ scanners
- **Pre-check** – Before uploading, the app checks for an existing report using SHA-256 (files) or URL hash (URLs)
- **Cancel button** – Cancel running scans at any time
- **Color-coded results** – Instantly see which scanners report threats
- **Settings dialog** – Conveniently store the API key inside the app

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

After the build, you will find the app without a bundled `.env` under `dist/virustotal_scanner`.

## Security Notes

- Never commit your `.env` file or API key.
- The `.env` file is already excluded by `.gitignore`.
- The app stores the API key in the system keyring when available, and falls back to a local `settings.json` with restricted permissions (`0o600`) if keyring is unavailable.

## License

MIT
