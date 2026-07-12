from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScannerVerdict:
    scanner_name: str
    category: str
    result: str | None

    @property
    def is_malicious(self) -> bool:
        return self.category in ("malicious", "suspicious")


@dataclass
class ScanResult:
    stats: dict[str, int] = field(default_factory=dict)
    verdicts: list[ScannerVerdict] = field(default_factory=list)
    error: str | None = None

    @property
    def total_scanners(self) -> int:
        return sum(self.stats.values()) if self.stats else len(self.verdicts)

    @property
    def malicious_count(self) -> int:
        return self.stats.get("malicious", 0) + self.stats.get("suspicious", 0)

    @classmethod
    def from_error(cls, message: str) -> ScanResult:
        return cls(error=message)

    @classmethod
    def from_api_response(cls, data: dict) -> ScanResult:
        attributes = data.get("data", {}).get("attributes", {})
        return cls._from_results(
            attributes.get("stats", {}),
            attributes.get("results", {}),
        )

    @classmethod
    def from_report(cls, data: dict) -> ScanResult:
        attributes = data.get("data", {}).get("attributes", {})
        return cls._from_results(
            attributes.get("last_analysis_stats", {}),
            attributes.get("last_analysis_results", {}),
        )

    @classmethod
    def _from_results(cls, stats: dict, results: dict) -> ScanResult:
        verdicts = []
        for scanner_name, detail in results.items():
            verdicts.append(
                ScannerVerdict(
                    scanner_name=scanner_name,
                    category=detail.get("category", "undetected"),
                    result=detail.get("result"),
                )
            )

        priority = {"malicious": 0, "suspicious": 1, "undetected": 2, "harmless": 3}
        verdicts.sort(key=lambda v: priority.get(v.category, 99))

        return cls(stats=stats, verdicts=verdicts)
