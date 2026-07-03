from __future__ import annotations
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
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

    def generate_sbom(self, session: Session, requirements_path: Path | None = None) -> dict:
        """Generate a CycloneDX 1.5 JSON SBOM from requirements.txt."""
        target_path = Path(session.target.path)
        req_path = requirements_path or (target_path / "requirements.txt")
        components = []
        if req_path.exists():
            for line in req_path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # Simple parsing: name==version, name>=version, etc.
                import re
                m = re.match(r"([a-zA-Z0-9_.\-]+)\s*([=<>!~]+)\s*([a-zA-Z0-9_.\-]+)", line)
                if m:
                    name, _, version = m.groups()
                    components.append({
                        "type": "library",
                        "name": name,
                        "version": version,
                        "purl": f"pkg:pypi/{name}@{version}",
                        "bom-ref": f"pkg:pypi/{name}@{version}",
                    })
                else:
                    # Unpinned dependency
                    components.append({
                        "type": "library",
                        "name": line.split()[0],
                        "version": "",
                        "purl": f"pkg:pypi/{line.split()[0]}",
                        "bom-ref": f"pkg:pypi/{line.split()[0]}",
                    })
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [
                    {
                        "vendor": "Secure Deploy Guard",
                        "name": "sdg",
                        "version": "0.2.0",
                    }
                ],
            },
            "components": components,
        }

    def sbom_to_json(self, session: Session, requirements_path: Path | None = None) -> str:
        return json.dumps(self.generate_sbom(session, requirements_path), indent=2)
