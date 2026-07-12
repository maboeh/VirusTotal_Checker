from models.scan_result import ScanResult, ScannerVerdict


def test_scan_result_from_api_response():
    data = {
        "data": {
            "attributes": {
                "stats": {"malicious": 1, "harmless": 2},
                "results": {
                    "A": {"category": "malicious", "result": "Trojan"},
                    "B": {"category": "harmless", "result": None},
                },
            }
        }
    }
    result = ScanResult.from_api_response(data)
    assert result.total_scanners == 3
    assert result.malicious_count == 1
    assert result.verdicts[0].scanner_name == "A"
    assert result.verdicts[0].is_malicious is True


def test_scan_result_from_report():
    data = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"suspicious": 1, "undetected": 1},
                "last_analysis_results": {
                    "A": {"category": "suspicious", "result": None},
                    "B": {"category": "undetected", "result": None},
                },
            }
        }
    }
    result = ScanResult.from_report(data)
    assert result.total_scanners == 2
    assert result.malicious_count == 1
    assert result.verdicts[0].is_malicious is True


def test_scan_result_from_error():
    result = ScanResult.from_error("Fehler")
    assert result.error == "Fehler"
    assert result.total_scanners == 0


def test_verdict_is_malicious():
    assert ScannerVerdict("X", "malicious", None).is_malicious is True
    assert ScannerVerdict("X", "suspicious", None).is_malicious is True
    assert ScannerVerdict("X", "harmless", None).is_malicious is False
