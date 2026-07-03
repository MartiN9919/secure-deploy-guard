from __future__ import annotations
import asyncio
import json
from pathlib import Path
from typing import Any
from sdg.agents.base import BaseAgent
from sdg.models import ScanReport, ScanTarget, Finding, Severity, ScanCategory
from sdg.mcp_servers.client import MCPClient


class SecretsAgent(BaseAgent):
    def __init__(self, config: dict[str, Any]):
        super().__init__("secrets", config)
        base = Path(__file__).resolve().parent.parent
        self.secrets_client = MCPClient(str(base / "mcp_servers" / "server_secrets.py"))

    def _findings_from_secrets(self, text: str) -> list[Finding]:
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
            severity = Severity(item.get("severity", "high"))
            findings.append(Finding(
                severity=severity,
                category=ScanCategory.HARDCODED_SECRET,
                message=f"{item.get('secret_type', 'Secret')} detected",
                file_path=item.get("file_path", ""),
                line_number=item.get("line_number"),
                snippet=item.get("line"),
                recommendation="Move secret to environment variables or a secrets manager",
            ))
        return findings

    async def _execute_async(self, target: ScanTarget) -> ScanReport:
        report = ScanReport(target=target)
        path = str(Path(target.path).resolve())

        try:
            secrets_text = await self.secrets_client.call_tool("scan_secrets", {"path": path})
        except Exception:
            secrets_text = "[]"

        if isinstance(secrets_text, str):
            for finding in self._findings_from_secrets(secrets_text):
                report.add_finding(finding)

        return report

    def execute(self, target: ScanTarget) -> ScanReport:
        return asyncio.run(self._execute_async(target))
