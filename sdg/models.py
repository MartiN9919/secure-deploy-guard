from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ScanCategory(str, Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    HARDCODED_SECRET = "hardcoded_secret"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    DEPENDENCY_VULN = "dependency_vulnerability"
    DOCKER_MISCONFIG = "docker_misconfiguration"
    K8S_MISCONFIG = "kubernetes_misconfiguration"
    TERRAFORM_MISCONFIG = "terraform_misconfiguration"
    CODE_QUALITY = "code_quality"
    BUFFER_OVERFLOW = "buffer_overflow"


@dataclass
class Finding:
    severity: Severity
    category: ScanCategory
    message: str
    file_path: str
    line_number: Optional[int] = None
    snippet: Optional[str] = None
    recommendation: Optional[str] = None


@dataclass
class ScanTarget:
    path: str
    rules: list[str] = field(default_factory=list)


@dataclass
class ScanReport:
    target: ScanTarget
    findings: list[Finding] = field(default_factory=list)
    trust_score: float = 1.0
    summary: dict = field(default_factory=dict)

    def add_finding(self, finding: Finding):
        self.findings.append(finding)

    def by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {}
        for f in self.findings:
            result.setdefault(f.severity, []).append(f)
        return result

    def passed(self) -> bool:
        return not any(
            f.severity == Severity.CRITICAL
            for f in self.findings
        )
