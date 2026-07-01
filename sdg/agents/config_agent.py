from __future__ import annotations
import asyncio
import json
from pathlib import Path
from typing import Any
from sdg.agents.base import BaseAgent
from sdg.models import ScanReport, ScanTarget, Finding, Severity, ScanCategory
from sdg.mcp_servers.client import MCPClient


class ConfigAgent(BaseAgent):
    def __init__(self, config: dict[str, Any]):
        super().__init__("config", config)
        base = Path(__file__).resolve().parent.parent
        self.docker_client = MCPClient(str(base / "mcp_servers" / "server_docker.py"))

    def _findings_from_docker(self, text: str) -> list[Finding]:
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
            # Skip "no issues" placeholder
            if "id" not in item and "message" in item:
                continue
            severity = Severity(item.get("severity", "medium"))
            file_path = item.get("file", "")
            title = item.get("title", item.get("message", "Docker misconfiguration"))
            findings.append(Finding(
                severity=severity,
                category=ScanCategory.DOCKER_MISCONFIG if item.get("file_type") == "dockerfile" else ScanCategory.K8S_MISCONFIG,
                message=title,
                file_path=file_path,
                recommendation=item.get("description", ""),
            ))
        return findings

    async def _execute_async(self, target: ScanTarget) -> ScanReport:
        report = ScanReport(target=target)
        path = str(Path(target.path).resolve())

        try:
            docker_text = await self.docker_client.call_tool("scan_dockerfile", {"path": path})
        except Exception:
            docker_text = "[]"

        if isinstance(docker_text, str):
            for finding in self._findings_from_docker(docker_text):
                report.add_finding(finding)

        return report

    def execute(self, target: ScanTarget) -> ScanReport:
        return asyncio.run(self._execute_async(target))
