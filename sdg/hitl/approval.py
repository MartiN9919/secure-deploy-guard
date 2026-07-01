from __future__ import annotations
from typing import Any
from sdg.orchestrator.session import Session
from sdg.hitl.vibe_diff import VibeDiff

class ApprovalGate:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.vibe_diff = VibeDiff(config)

    def request(self, session: Session) -> bool:
        if self.config.get("auto_approve", False): return True
        summary = self.vibe_diff.generate_summary(session.get_all_findings())
        print("=" * 60)
        print("HUMAN APPROVAL REQUIRED")
        print("=" * 60)
        print(summary)
        print(f"\nTrust Score: {session.trust_score:.2f}")
        print("\nApprove? (y/N): ", end="")
        try:
            return input().strip().lower() == "y"
        except (EOFError, KeyboardInterrupt):
            return False
