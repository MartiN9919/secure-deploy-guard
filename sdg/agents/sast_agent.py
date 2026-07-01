from __future__ import annotations
import asyncio
import json
from pathlib import Path
from typing import Any
from sdg.agents.base import BaseAgent
from sdg.models import ScanReport, ScanTarget, Finding, Severity, ScanCategory
from sdg.mcp_servers.client import MCPClient


class SASTAgent(BaseAgent):
    def __init__(self, config: dict[str, Any]):
        super().__init__("sast", config)
        base = Path(__file__).resolve().parent.parent
        self.semgrep_client = MCPClient(str(base / "mcp_servers" / "server_semgrep.py"))
        self.bandit_client = MCPClient(str(base / "mcp_servers" / "server_bandit.py"))

    def _findings_from_semgrep(self, text: str) -> list[Finding]:
        findings = []
        try:
            data = json.loads(text)
        except Exception:
            return findings
        if not isinstance(data, list):
            return findings
        for item in data:
            if not isinstance(item, dict):
                continue
            severity = Severity(item.get("severity", "medium"))
            category = ScanCategory(item.get("category", "code_quality"))
            findings.append(Finding(
                severity=severity,
                category=category,
                message=item.get("message", ""),
                file_path=item.get("file", item.get("file_path", "")),
                line_number=item.get("line", item.get("line_number")),
                snippet=item.get("snippet"),
                recommendation=item.get("recommendation"),
            ))
        return findings

    def _findings_from_bandit(self, text: str) -> list[Finding]:
        findings = []
        try:
            data = json.loads(text)
        except Exception:
            return findings
        for item in data.get("results", []):
            severity_map = {
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
            }
            severity = severity_map.get(item.get("issue_severity"), Severity.MEDIUM)
            findings.append(Finding(
                severity=severity,
                category=ScanCategory.CODE_QUALITY,
                message=item.get("issue_text", ""),
                file_path=item.get("filename", ""),
                line_number=item.get("line_number"),
                snippet=item.get("code"),
                recommendation=item.get("issue_text", ""),
            ))
        return findings

    async def _execute_async(self, target: ScanTarget) -> ScanReport:
        report = ScanReport(target=target)
        path = str(Path(target.path).resolve())

        semgrep_text, bandit_text = await asyncio.gather(
            self.semgrep_client.call_tool("semgrep_scan", {"path": path, "rules": "owasp-top-10"}),
            self.bandit_client.call_tool("bandit_scan", {"path": path, "severity": "low"}),
            return_exceptions=True,
        )

        if isinstance(semgrep_text, str):
            for finding in self._findings_from_semgrep(semgrep_text):
                report.add_finding(finding)

        if isinstance(bandit_text, str):
            for finding in self._findings_from_bandit(bandit_text):
                report.add_finding(finding)

        return report

    def execute(self, target: ScanTarget) -> ScanReport:
        return asyncio.run(self._execute_async(target))
