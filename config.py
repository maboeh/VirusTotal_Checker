from __future__ import annotations

import json
import os
import platform
from pathlib import Path

from dotenv import load_dotenv

try:
    import keyring
except Exception:
    keyring = None

PROJECT_DIR = Path(__file__).resolve().parent

load_dotenv(PROJECT_DIR / ".env", override=False)

APP_NAME = "VirusTotal Scanner"
VERSION = "1.0.1"

GITHUB_OWNER = "maboeh"
GITHUB_REPO = "VirusTotal_Checker"

KEYRING_SERVICE = "VirusTotalScanner"
KEYRING_USERNAME = "api_key"


def _settings_dir() -> Path:
    system = platform.system()
    if system == "Windows":
        base = Path(os.environ.get("APPDATA", Path.home()))
    elif system == "Darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path.home() / ".config"
    settings_dir = base / "VirusTotalScanner"
    settings_dir.mkdir(parents=True, exist_ok=True)
    return settings_dir


SETTINGS_PATH = _settings_dir() / "settings.json"


def _load_settings() -> dict:
    if SETTINGS_PATH.exists():
        try:
            return json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
    return {}


def _save_settings(settings: dict) -> None:
    SETTINGS_PATH.write_text(json.dumps(settings, indent=2), encoding="utf-8")
    try:
        os.chmod(SETTINGS_PATH, 0o600)
    except OSError:
        pass


def _keyring_get_password() -> str | None:
    if keyring is None:
        return None
    try:
        password = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
        return password.strip() if isinstance(password, str) else None
    except Exception:
        return None


def _keyring_set_password(api_key: str) -> bool:
    if keyring is None:
        return False
    try:
        keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, api_key)
        return True
    except Exception:
        return False


def _keyring_delete_password() -> bool:
    if keyring is None:
        return False
    try:
        keyring.delete_password(KEYRING_SERVICE, KEYRING_USERNAME)
        return True
    except Exception:
        return False


def _get_api_key() -> str:
    env_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if env_key:
        return env_key

    keyring_key = _keyring_get_password()
    if keyring_key:
        return keyring_key

    legacy_key = _load_settings().get("api_key")
    return legacy_key.strip() if isinstance(legacy_key, str) else ""


VIRUSTOTAL_API_KEY = _get_api_key()
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"

POLL_INTERVAL_SECONDS = 5
POLL_MAX_INTERVAL_SECONDS = 30
POLL_MAX_ATTEMPTS = 40
MAX_FILE_SIZE_MB = 650
MAX_URL_LENGTH = 2048


def save_api_key(api_key: str) -> None:
    global VIRUSTOTAL_API_KEY
    api_key = api_key.strip()
    VIRUSTOTAL_API_KEY = api_key

    if not api_key:
        _keyring_delete_password()
        settings = _load_settings()
        settings.pop("api_key", None)
        _save_settings(settings)
        return

    if _keyring_set_password(api_key):
        settings = _load_settings()
        if "api_key" in settings:
            del settings["api_key"]
            _save_settings(settings)
        return

    _keyring_delete_password()
    settings = _load_settings()
    settings["api_key"] = api_key
    _save_settings(settings)
