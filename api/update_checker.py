from __future__ import annotations

import platform
import re
from dataclasses import dataclass

import requests

import config


@dataclass(frozen=True)
class UpdateInfo:
    latest_version: str
    release_url: str
    download_url: str | None


def _normalize_version(version: str) -> tuple[int, ...]:
    """Wandelt 'v1.2.3' oder '1.2.3' in (1, 2, 3) um."""
    cleaned = re.sub(r"[^0-9.]", "", version)
    parts = [int(p) if p.isdigit() else 0 for p in cleaned.split(".")]
    return tuple(parts)


def is_newer(latest: str, current: str) -> bool:
    return _normalize_version(latest) > _normalize_version(current)


def _platform_asset_keyword() -> str:
    system = platform.system()
    if system == "Windows":
        return "Windows"
    if system == "Darwin":
        return "macOS"
    return "Linux"


def _select_asset(assets: list[dict]) -> str | None:
    keyword = _platform_asset_keyword()
    # Erst nach Plattform-Keyword suchen
    for asset in assets:
        name = asset.get("name", "")
        if keyword.lower() in name.lower():
            return asset.get("browser_download_url")
    # Fallback: erstes Asset
    if assets:
        return assets[0].get("browser_download_url")
    return None


def check_for_update(
    current_version: str | None = None,
    timeout: float = 10.0,
) -> UpdateInfo | None:
    """
    Fragt die GitHub Releases API nach der neuesten Version ab.

    Liefert ein UpdateInfo, wenn eine neuere Version existiert,
    sonst None. Im Fehlerfall wird ebenfalls None zurückgegeben.
    """
    if current_version is None:
        current_version = config.VERSION

    url = (
        f"https://api.github.com/repos/"
        f"{config.GITHUB_OWNER}/{config.GITHUB_REPO}/releases/latest"
    )
    try:
        response = requests.get(
            url,
            headers={"Accept": "application/vnd.github+json"},
            timeout=timeout,
        )
        response.raise_for_status()
    except (requests.RequestException, ValueError):
        return None

    data = response.json()
    tag_name = data.get("tag_name", "")
    release_url = data.get("html_url", "")
    assets = data.get("assets", [])
    download_url = _select_asset(assets)

    if not tag_name:
        return None

    if not is_newer(tag_name, current_version):
        return None

    return UpdateInfo(
        latest_version=tag_name,
        release_url=release_url,
        download_url=download_url,
    )
