from __future__ import annotations
from typing import Any
from sdg.models import Finding

class VibeDiff:
    def __init__(self, config: dict[str, Any]):
        self.config = config

    def generate_summary(self, findings: list[Finding]) -> str:
        if not findings: return "No security issues found."
        critical = [f for f in findings if f.severity.value == "critical"]
        high = [f for f in findings if f.severity.value == "high"]
        parts = ["## Security Scan Summary (Plain English)", ""]
        if critical:
            parts.append(f"**{len(critical)} critical issue(s) — must fix before deploy:**")
            for f in critical[:5]: parts.append(f"- {f.message} in {f.file_path}")
        if high:
            parts.append(f"**{len(high)} high severity issue(s):**")
            for f in high[:5]: parts.append(f"- {f.message} in {f.file_path}")
        if not critical and not high: parts.append("No critical or high issues. Scan passed.")
        return "\n".join(parts)
