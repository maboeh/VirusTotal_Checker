import json
import os
import stat
from pathlib import Path
from unittest.mock import patch

import config


def test_save_api_key_sets_permissions(tmp_path: Path, monkeypatch):
    settings_path = tmp_path / "settings.json"
    monkeypatch.setattr(config, "SETTINGS_PATH", settings_path)
    monkeypatch.setattr(config, "_load_settings", lambda: {})
    monkeypatch.setattr(config, "_keyring_set_password", lambda api_key: False)
    monkeypatch.setattr(config, "_keyring_get_password", lambda: None)
    monkeypatch.setattr(config, "_keyring_delete_password", lambda: True)
    config.save_api_key("test-key-123")
    mode = stat.S_IMODE(os.stat(settings_path).st_mode)
    assert mode == 0o600
    data = json.loads(settings_path.read_text())
    assert data["api_key"] == "test-key-123"


def test_save_api_key_updates_global(tmp_path: Path, monkeypatch):
    settings_path = tmp_path / "settings.json"
    monkeypatch.setattr(config, "SETTINGS_PATH", settings_path)
    monkeypatch.setattr(config, "_load_settings", lambda: {})
    monkeypatch.setattr(config, "_keyring_set_password", lambda api_key: False)
    monkeypatch.setattr(config, "_keyring_get_password", lambda: None)
    monkeypatch.setattr(config, "_keyring_delete_password", lambda: True)
    config.save_api_key("new-key")
    assert config.VIRUSTOTAL_API_KEY == "new-key"


def test_save_api_key_uses_keyring(tmp_path: Path, monkeypatch):
    settings_path = tmp_path / "settings.json"
    monkeypatch.setattr(config, "SETTINGS_PATH", settings_path)
    monkeypatch.setattr(config, "_load_settings", lambda: {"api_key": "legacy-key"})
    stored = {}

    def fake_set_password(api_key):
        stored["keyring"] = api_key
        return True

    monkeypatch.setattr(config, "_keyring_set_password", fake_set_password)
    monkeypatch.setattr(config, "_keyring_get_password", lambda: stored.get("keyring"))
    monkeypatch.setattr(config, "_keyring_delete_password", lambda: True)
    config.save_api_key("new-keyring-key")
    assert config.VIRUSTOTAL_API_KEY == "new-keyring-key"
    data = json.loads(settings_path.read_text())
    assert "api_key" not in data


def test_get_api_key_prefers_env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "env-key")
    monkeypatch.setattr(config, "_keyring_get_password", lambda: "keyring-key")
    monkeypatch.setattr(config, "_load_settings", lambda: {"api_key": "legacy-key"})
    assert config._get_api_key() == "env-key"


def test_get_api_key_prefers_keyring_over_legacy(monkeypatch):
    monkeypatch.setattr(config, "_keyring_get_password", lambda: "keyring-key")
    monkeypatch.setattr(config, "_load_settings", lambda: {"api_key": "legacy-key"})
    assert config._get_api_key() == "keyring-key"


def test_config_constants():
    assert config.POLL_INTERVAL_SECONDS == 5
    assert config.POLL_MAX_INTERVAL_SECONDS == 30
    assert config.MAX_URL_LENGTH == 2048
    assert config.MAX_FILE_SIZE_MB == 650
