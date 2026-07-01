from __future__ import annotations
import uuid
from typing import Any
from sdg.models import ScanTarget, Finding, Severity


class Session:
    def __init__(self, target: ScanTarget, config: dict[str, Any]):
        self.session_id = str(uuid.uuid4())
        self.target = target
        self.config = config
        self.agent_results: dict[str, Any] = {}
        self.trust_score: float = 1.0
        self.approved: bool = False

    def add_result(self, name: str, report: Any) -> None:
        self.agent_results[name] = report

    def get_all_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        for report in self.agent_results.values():
            if hasattr(report, "findings"):
                findings.extend(report.findings)
        return findings

    def summary(self) -> dict:
        findings = self.get_all_findings()
        by_severity: dict[str, int] = {}
        for f in findings:
            key = f.severity.value if hasattr(f, "severity") else "unknown"
            by_severity[key] = by_severity.get(key, 0) + 1
        return {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "agents_run": list(self.agent_results.keys()),
        }
