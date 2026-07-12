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
On macOS, a `VirusTotal Scanner.app` bundle is also created in `dist/`.

## Installation (End Users)

Download the latest release for your platform from the
[Releases page](https://github.com/maboeh/VirusTotal_Checker/releases):

| Platform | File |
|----------|------|
| macOS (Apple Silicon) | `VirusTotal-Scanner-macOS.zip` |
| Windows | `VirusTotal-Scanner-Windows.zip` |
| Linux | `VirusTotal-Scanner-Linux.tar.gz` |

### macOS

1. Unzip `VirusTotal-Scanner-macOS.zip`.
2. Move `VirusTotal Scanner.app` to your `Applications` folder.
3. Because the app is **not code-signed**, macOS Gatekeeper will block it on first launch. To open it anyway:
   - Right-click `VirusTotal Scanner.app` and select **Open**.
   - Confirm the dialog with **Open**.
   - Alternatively, run `xattr -d com.apple.quarantine "/Applications/VirusTotal Scanner.app"` in Terminal.

### Windows

1. Unzip `VirusTotal-Scanner-Windows.zip`.
2. Because the app is **not code-signed**, Windows SmartScreen may show a warning. Click **More info** → **Run anyway**.
3. Run `virustotal_scanner.exe` from the extracted folder.

### Linux

1. Extract `VirusTotal-Scanner-Linux.tar.gz`.
2. Run `./virustotal_scanner` from the extracted folder.
   You may need to install `libxcb-cursor0` and `libxkbcommon-x11-0` for the UI to render correctly.

## Releases & Updates

### Release Process

Releases are triggered by Git tags. To publish a new release:

1. Bump `VERSION` in `config.py` (e.g. `VERSION = "1.0.1"`).
2. Commit the change.
3. Tag the commit: `git tag v1.0.1`.
4. Push: `git push && git push --tags`.

The GitHub Actions workflow (`.github/workflows/release.yml`) automatically builds the app for macOS, Windows, and Linux and attaches the artifacts to a new GitHub Release.

### In-App Updates

The app checks for updates on startup by querying the GitHub Releases API. If a newer version is available, a dialog shows the current and new version with two options:

- **Install & Restart** – Downloads the new version, replaces the current app, and restarts automatically.
- **Later** – Skips the update; the dialog will reappear on the next launch.

You can also view the release notes by clicking **Release-Notes**.

## Security Notes

- Never commit your `.env` file or API key.
- The `.env` file is already excluded by `.gitignore`.
- The app stores the API key in the system keyring when available, and falls back to a local `settings.json` with restricted permissions (`0o600`) if keyring is unavailable.

## License

MIT
