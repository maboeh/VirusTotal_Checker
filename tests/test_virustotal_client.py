import base64
import hashlib
import threading
from pathlib import Path
from unittest.mock import patch

import config
import responses

from api.virustotal_client import VirusTotalClient


@responses.activate
def test_scan_url_uses_existing_report():
    client = VirusTotalClient(api_key="test")
    url = "https://example.com"
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    responses.add(
        responses.GET,
        f"{config.VIRUSTOTAL_BASE_URL}/urls/{url_id}",
        json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {"harmless": 2},
                    "last_analysis_results": {
                        "A": {"category": "harmless", "result": None},
                        "B": {"category": "harmless", "result": None},
                    },
                }
            }
        },
        status=200,
    )
    result = client.scan_url(url)
    assert result.error is None
    assert result.total_scanners == 2


def test_scan_url_empty_string():
    client = VirusTotalClient(api_key="test")
    result = client.scan_url("   ")
    assert result.error is not None
    assert "gültige URL" in result.error


def test_scan_url_no_netloc():
    client = VirusTotalClient(api_key="test")
    result = client.scan_url("https://")
    assert result.error is not None
    assert "gültige URL" in result.error


def test_scan_url_too_long():
    client = VirusTotalClient(api_key="test")
    long_url = "https://example.com/" + "a" * 2100
    result = client.scan_url(long_url)
    assert result.error is not None
    assert "zu lang" in result.error


def test_scan_url_too_long_without_scheme():
    client = VirusTotalClient(api_key="test")
    long_url = "example.com/" + "a" * 2041
    result = client.scan_url(long_url)
    assert result.error is not None
    assert "zu lang" in result.error


def test_validate_url_length_after_scheme():
    client = VirusTotalClient(api_key="test")
    url = "https://example.com/" + "a" * 2028
    validated = client._validate_url(url)
    assert isinstance(validated, str)
    assert len(validated) == config.MAX_URL_LENGTH


@responses.activate
def test_scan_url_401_invalid_key():
    client = VirusTotalClient(api_key="invalid")
    url = "https://example.com"
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    responses.add(
        responses.GET,
        f"{config.VIRUSTOTAL_BASE_URL}/urls/{url_id}",
        status=401,
    )
    result = client.scan_url(url)
    assert result.error is not None
    assert "Ungültiger API-Key" in result.error


@responses.activate
def test_scan_url_gets_same_host_redirect():
    client = VirusTotalClient(api_key="test")
    url = "https://example.com"
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    redirect_url = f"{config.VIRUSTOTAL_BASE_URL}/urls/{url_id}-redirected"

    responses.add(
        responses.GET,
        f"{config.VIRUSTOTAL_BASE_URL}/urls/{url_id}",
        status=302,
        headers={"Location": redirect_url},
    )
    responses.add(
        responses.GET,
        redirect_url,
        json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {"harmless": 1},
                    "last_analysis_results": {
                        "A": {"category": "harmless", "result": None},
                    },
                }
            }
        },
        status=200,
    )
    result = client._get_url_report(url, None)
    assert result.error is None
    assert result.total_scanners == 1


@responses.activate
def test_scan_url_blocks_cross_origin_redirect():
    client = VirusTotalClient(api_key="test")
    url = "https://example.com"
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    responses.add(
        responses.GET,
        f"{config.VIRUSTOTAL_BASE_URL}/urls/{url_id}",
        status=302,
        headers={"Location": "https://evil.com/steal"},
    )
    result = client._get_url_report(url, None)
    assert result.error is not None
    assert "Cross-origin redirect" in result.error


@responses.activate
def test_scan_file_not_found():
    client = VirusTotalClient(api_key="test")
    result = client.scan_file("/tmp/does-not-exist-12345.bin")
    assert result.error is not None


@responses.activate
def test_scan_file_hash_lookup_hits(tmp_path: Path):
    client = VirusTotalClient(api_key="test")
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"hello world")
    file_hash = hashlib.sha256(b"hello world").hexdigest()

    responses.add(
        responses.GET,
        f"{config.VIRUSTOTAL_BASE_URL}/files/{file_hash}",
        json={
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 1, "harmless": 2},
                    "last_analysis_results": {
                        "A": {"category": "malicious", "result": "Trojan"},
                        "B": {"category": "harmless", "result": None},
                        "C": {"category": "harmless", "result": None},
                    },
                }
            }
        },
        status=200,
    )
    result = client.scan_file(str(test_file))
    assert result.error is None
    assert result.malicious_count == 1
    assert result.total_scanners == 3


@responses.activate
def test_scan_file_hash_not_found_triggers_upload(tmp_path: Path):
    client = VirusTotalClient(api_key="test")
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"hello")
    file_hash = hashlib.sha256(b"hello").hexdigest()

    responses.add(
        responses.GET,
        f"{config.VIRUSTOTAL_BASE_URL}/files/{file_hash}",
        status=404,
    )
    responses.add(
        responses.POST,
        f"{config.VIRUSTOTAL_BASE_URL}/files",
        json={"data": {"id": "analysis-123"}},
        status=200,
    )
    responses.add(
        responses.GET,
        f"{config.VIRUSTOTAL_BASE_URL}/analyses/analysis-123",
        json={
            "data": {
                "attributes": {
                    "status": "completed",
                    "stats": {"harmless": 1},
                    "results": {
                        "A": {"category": "harmless", "result": None},
                    },
                }
            }
        },
        status=200,
    )
    with patch("time.sleep"):
        result = client.scan_file(str(test_file))
    assert result.error is None
    assert result.total_scanners == 1


def test_cancel_event_during_hashing(tmp_path: Path):
    client = VirusTotalClient(api_key="test")
    test_file = tmp_path / "large.bin"
    test_file.write_bytes(b"x" * (1024 * 1024 + 100))
    cancel_event = threading.Event()
    cancel_event.set()
    result = client.scan_file(str(test_file), cancel_event=cancel_event)
    assert result.error is not None
    assert "abgebrochen" in result.error.lower()


def test_scan_file_too_large(tmp_path: Path, monkeypatch):
    client = VirusTotalClient(api_key="test")
    test_file = tmp_path / "big.bin"
    test_file.write_bytes(b"x" * 100)

    import os
    real_stat = os.stat

    def fake_stat(path, *args, **kwargs):
        result = real_stat(path, *args, **kwargs)
        if str(path) == str(test_file):
            class FakeStatResult:
                st_mode = result.st_mode
                st_size = 700 * 1024 * 1024
                st_ino = result.st_ino
                st_dev = result.st_dev
                st_nlink = result.st_nlink
                st_uid = result.st_uid
                st_gid = result.st_gid
                st_atime = result.st_atime
                st_mtime = result.st_mtime
                st_ctime = result.st_ctime
            return FakeStatResult()
        return result

    monkeypatch.setattr(os, "stat", fake_stat)
    result = client.scan_file(str(test_file))
    assert result.error is not None
    assert "zu groß" in result.error


def test_no_api_key_configured():
    client = VirusTotalClient(api_key="")
    result = client.scan_url("https://example.com")
    assert result.error is not None
    assert "API-Key" in result.error
