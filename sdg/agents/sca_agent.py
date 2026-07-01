from __future__ import annotations
from pathlib import Path
from typing import Any
import re
from sdg.agents.base import BaseAgent
from sdg.models import ScanReport, ScanTarget, Finding, Severity, ScanCategory

KNOWN_VULN = {
    "django": [{"versions": "<3.2.18", "cve": "CVE-2023-23969", "severity": Severity.HIGH}, {"versions": "<4.2.7", "cve": "CVE-2023-46695", "severity": Severity.HIGH}],
    "flask": [{"versions": "<2.3.2", "cve": "CVE-2023-30861", "severity": Severity.MEDIUM}],
    "requests": [{"versions": "<2.31.0", "cve": "CVE-2023-32681", "severity": Severity.MEDIUM}],
    "pillow": [{"versions": "<10.0.0", "cve": "CVE-2023-44271", "severity": Severity.HIGH}],
    "cryptography": [{"versions": "<41.0.0", "cve": "CVE-2023-23931", "severity": Severity.HIGH}],
}

def _parse_version(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v))

def _in_range(version: str, spec: str) -> bool:
    v = _parse_version(version)
    if spec.startswith("<"):
        return v < _parse_version(spec[1:])
    if ">=" in spec and "<" in spec:
        parts = re.findall(r"[\d.]+", spec)
        return _parse_version(parts[0]) <= v < _parse_version(parts[1])
    return False

class SCAAgent(BaseAgent):
    def __init__(self, config: dict[str, Any]):
        super().__init__("sca", config)

    def execute(self, target: ScanTarget) -> ScanReport:
        report = ScanReport(target=target)
        req_path = Path(target.path) / "requirements.txt"
        if not req_path.exists():
            report.add_finding(Finding(severity=Severity.MEDIUM, category=ScanCategory.DEPENDENCY_VULN, message="No requirements.txt found", file_path=str(req_path), recommendation="Create requirements.txt with pinned deps"))
            return report
        try:
            content = req_path.read_text()
        except Exception:
            return report
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            m = re.match(r"([a-zA-Z0-9_.-]+)\s*[=<>!]+\s*([\d.]+)", line)
            if not m:
                continue
            pkg, ver = m.group(1).lower(), m.group(2)
            if pkg in KNOWN_VULN:
                for vuln in KNOWN_VULN[pkg]:
                    if _in_range(ver, vuln["versions"]):
                        report.add_finding(Finding(severity=vuln["severity"], category=ScanCategory.DEPENDENCY_VULN, message=f"{pkg} {ver} — {vuln['cve']}", file_path=str(req_path), recommendation=f"Upgrade {pkg}"))
        if not report.findings:
            report.add_finding(Finding(severity=Severity.LOW, category=ScanCategory.CODE_QUALITY, message="No known vulnerabilities", file_path=str(req_path)))
        return report
