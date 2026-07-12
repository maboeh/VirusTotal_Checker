from unittest.mock import patch

import responses

from api.virustotal_client import VirusTotalClient


@responses.activate
def test_polling_completes_after_queued():
    client = VirusTotalClient(api_key="test")
    analysis_id = "test-analysis"
    url = "https://example.com"
    url_id = "aHR0cHM6Ly9leGFtcGxlLmNvbQ"

    responses.add(
        responses.GET,
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        status=404,
    )
    responses.add(
        responses.POST,
        "https://www.virustotal.com/api/v3/urls",
        json={"data": {"id": analysis_id}},
        status=200,
    )
    responses.add(
        responses.GET,
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        json={"data": {"attributes": {"status": "queued"}}},
        status=200,
    )
    responses.add(
        responses.GET,
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        json={
            "data": {
                "attributes": {
                    "status": "completed",
                    "stats": {"harmless": 1},
                    "results": {"A": {"category": "harmless", "result": None}},
                }
            }
        },
        status=200,
    )
    with patch("time.sleep"):
        result = client.scan_url(url)
    assert result.error is None
    assert result.total_scanners == 1


@responses.activate
def test_polling_401_aborts_immediately():
    client = VirusTotalClient(api_key="invalid")
    analysis_id = "test-analysis"
    url = "https://example.com"
    url_id = "aHR0cHM6Ly9leGFtcGxlLmNvbQ"

    responses.add(
        responses.GET,
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        status=404,
    )
    responses.add(
        responses.POST,
        "https://www.virustotal.com/api/v3/urls",
        json={"data": {"id": analysis_id}},
        status=200,
    )
    responses.add(
        responses.GET,
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        status=401,
    )
    with patch("time.sleep"):
        result = client.scan_url(url)
    assert result.error is not None
    assert "Ungültiger API-Key" in result.error
    assert len(responses.calls) <= 4


@responses.activate
def test_polling_429_with_retry_after_then_success():
    client = VirusTotalClient(api_key="test")
    analysis_id = "test-analysis"
    url = "https://example.com"
    url_id = "aHR0cHM6Ly9leGFtcGxlLmNvbQ"

    responses.add(
        responses.GET,
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        status=404,
    )
    responses.add(
        responses.POST,
        "https://www.virustotal.com/api/v3/urls",
        json={"data": {"id": analysis_id}},
        status=200,
    )
    responses.add(
        responses.GET,
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        status=429,
        headers={"Retry-After": "2"},
    )
    responses.add(
        responses.GET,
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        json={
            "data": {
                "attributes": {
                    "status": "completed",
                    "stats": {"harmless": 1},
                    "results": {"A": {"category": "harmless", "result": None}},
                }
            }
        },
        status=200,
    )
    with patch("time.sleep"):
        result = client.scan_url(url)
    assert result.error is None
    assert result.total_scanners == 1


@responses.activate
def test_polling_429_with_http_date_retry_after():
    client = VirusTotalClient(api_key="test")
    analysis_id = "test-analysis"
    url = "https://example.com"
    url_id = "aHR0cHM6Ly9leGFtcGxlLmNvbQ"

    responses.add(
        responses.GET,
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        status=404,
    )
    responses.add(
        responses.POST,
        "https://www.virustotal.com/api/v3/urls",
        json={"data": {"id": analysis_id}},
        status=200,
    )
    responses.add(
        responses.GET,
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        status=429,
        headers={"Retry-After": "Wed, 21 Oct 2025 07:28:00 GMT"},
    )
    responses.add(
        responses.GET,
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        json={
            "data": {
                "attributes": {
                    "status": "completed",
                    "stats": {"harmless": 1},
                    "results": {"A": {"category": "harmless", "result": None}},
                }
            }
        },
        status=200,
    )
    with patch("time.sleep"):
        result = client.scan_url(url)
    assert result.error is None
