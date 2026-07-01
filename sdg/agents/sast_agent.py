from __future__ import annotations
from pathlib import Path
from typing import Any
from sdg.agents.base import BaseAgent
from sdg.models import ScanReport, ScanTarget, Finding, Severity, ScanCategory
from sdg.utils.patterns import scan_with_patterns, EXCLUDED_DIRS

class SASTAgent(BaseAgent):
    def __init__(self, config: dict[str, Any]):
        super().__init__("sast", config)

    def execute(self, target: ScanTarget) -> ScanReport:
        report = ScanReport(target=target)
        path = Path(target.path)
        exts = ["*.py", "*.js", "*.c", "*.cpp", "*.cs", "*.java", "*.go", "*.rb"]
        all_files = []
        for ext in exts:
            all_files.extend(path.rglob(ext))
        files = [f for f in all_files if not any(p in f.parts for p in EXCLUDED_DIRS)]
        for f in files:
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
                for finding in scan_with_patterns(str(f), content):
                    report.add_finding(finding)
            except Exception:
                continue
        return report
