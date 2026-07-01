from __future__ import annotations
from typing import Optional
from sdg.orchestrator.session import Session

class BlueTeam:
    def __init__(self): pass
    def check(self, session: Session) -> Optional[str]:
        findings = session.get_all_findings()
        if len(session.agent_results) > 5: return f"Too many agents: {len(session.agent_results)}"
        if len(findings) > 10000: return f"Too many findings: {len(findings)}"
        if sum(1 for f in findings if f.severity.value == "critical") > 500: return "Critical spike detected"
        return None
