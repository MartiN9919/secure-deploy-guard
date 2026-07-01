from __future__ import annotations
from datetime import datetime, timezone
from sdg.orchestrator.session import Session

class ReportGenerator:
    def generate(self, session: Session) -> dict:
        findings = session.get_all_findings()
        by_severity = session.summary().get("by_severity", {})
        return {
            "session_id": session.session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": str(session.target.path),
            "trust_score": session.trust_score,
            "summary": {"total_findings": len(findings), "critical": by_severity.get("critical", 0), "high": by_severity.get("high", 0), "medium": by_severity.get("medium", 0), "low": by_severity.get("low", 0)},
            "findings": [{"severity": f.severity.value, "category": f.category.value, "message": f.message, "file": f.file_path, "line": f.line_number, "recommendation": f.recommendation} for f in findings],
            "approved": session.approved,
        }

    def to_markdown(self, session: Session) -> str:
        r = self.generate(session)
        lines = [f"# Secure Deploy Guard Report\n**Session:** {r['session_id']}\n**Target:** {r['target']}\n**Trust Score:** {r['trust_score']:.2f}\n**Approved:** {'Yes' if r['approved'] else 'No'}\n", "## Summary\n| Severity | Count |\n|----------|-------|"]
        for s in ["critical", "high", "medium", "low"]: lines.append(f"| {s.title()} | {r['summary'].get(s, 0)} |")
        if r["findings"]:
            lines.extend(["", "## Findings"])
            for f in r["findings"]:
                loc = f"({f['file']}:{f['line']})" if f.get("line") else f"({f['file']})"
                lines.append(f"- **[{f['severity'].upper()}]** {f['category']}: {f['message']} {loc}")
                if f.get("recommendation"): lines.append(f"  - *Fix:* {f['recommendation']}")
        return "\n".join(lines)
