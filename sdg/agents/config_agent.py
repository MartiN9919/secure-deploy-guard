from __future__ import annotations
from pathlib import Path
from typing import Any
import yaml
from sdg.agents.base import BaseAgent
from sdg.models import ScanReport, ScanTarget, Finding, Severity, ScanCategory
from sdg.utils.patterns import EXCLUDED_DIRS

def _should_check(path: Path) -> bool:
    return not any(p in path.parts for p in EXCLUDED_DIRS)

class ConfigAgent(BaseAgent):
    def __init__(self, config: dict[str, Any]):
        super().__init__("config", config)

    def execute(self, target: ScanTarget) -> ScanReport:
        report = ScanReport(target=target)
        path = Path(target.path)
        
        for df in list(path.rglob("Dockerfile*")):
            if not _should_check(df):
                continue
            try:
                lines = df.read_text().splitlines()
            except Exception:
                continue
            if not any(l.strip().startswith("USER") for l in lines):
                report.add_finding(Finding(severity=Severity.CRITICAL, category=ScanCategory.DOCKER_MISCONFIG, message="No USER directive — runs as root", file_path=str(df), recommendation="Add USER nonroot"))
            if not any(l.strip().startswith("HEALTHCHECK") for l in lines):
                report.add_finding(Finding(severity=Severity.MEDIUM, category=ScanCategory.DOCKER_MISCONFIG, message="No HEALTHCHECK", file_path=str(df), recommendation="Add HEALTHCHECK"))
            if any(":latest" in l for l in lines if l.strip().startswith("FROM")):
                report.add_finding(Finding(severity=Severity.HIGH, category=ScanCategory.DOCKER_MISCONFIG, message="Uses :latest tag", file_path=str(df), recommendation="Pin to specific version"))

        for compose in list(path.rglob("docker-compose*.yml")) + list(path.rglob("docker-compose*.yaml")):
            if not _should_check(compose):
                continue
            try:
                data = yaml.safe_load(compose.read_text())
                for svc_name, svc in (data or {}).get("services", {}).items():
                    if isinstance(svc, dict) and svc.get("privileged", False):
                        report.add_finding(Finding(severity=Severity.CRITICAL, category=ScanCategory.DOCKER_MISCONFIG, message=f"Service '{svc_name}' privileged", file_path=str(compose), recommendation="Remove privileged: true"))
            except Exception:
                continue

        for kf in list(path.rglob("*.yaml")) + list(path.rglob("*.yml")):
            if not _should_check(kf):
                continue
            try:
                data = yaml.safe_load(kf.read_text())
                if not isinstance(data, dict) or data.get("kind", "") not in ("Pod", "Deployment", "StatefulSet"):
                    continue
                spec = data.get("spec", {})
                if data["kind"] != "Pod":
                    spec = spec.get("template", {}).get("spec", {})
                for c in spec.get("containers", []):
                    if not c.get("resources", {}).get("limits"):
                        report.add_finding(Finding(severity=Severity.MEDIUM, category=ScanCategory.K8S_MISCONFIG, message=f"Container '{c.get('name')}' missing limits", file_path=str(kf), recommendation="Set resource limits"))
                    sc = c.get("securityContext", {})
                    if not sc.get("runAsNonRoot"):
                        report.add_finding(Finding(severity=Severity.HIGH, category=ScanCategory.K8S_MISCONFIG, message=f"Container '{c.get('name')}' may run as root", file_path=str(kf), recommendation="Set runAsNonRoot: true"))
            except Exception:
                continue

        return report
