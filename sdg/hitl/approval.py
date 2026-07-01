from __future__ import annotations
import sys
from typing import Any
from sdg.orchestrator.session import Session
from sdg.hitl.vibe_diff import VibeDiff

YES_ANSWERS = {"y", "yes", "д", "да", "+", "1"}
NO_ANSWERS = {"n", "no", "н", "нет", "-", "0"}

class ApprovalGate:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.vibe_diff = VibeDiff(config)

    def _read_input(self) -> str:
        try:
            # Read raw bytes to survive non-UTF-8 terminals, then decode
            # with replacement so Cyrillic/latin mix does not crash.
            data = sys.stdin.buffer.readline()
            return data.decode(sys.stdin.encoding or "utf-8", errors="replace").strip()
        except (EOFError, KeyboardInterrupt, OSError):
            return ""

    def request(self, session: Session) -> bool:
        if self.config.get("auto_approve", False): return True
        summary = self.vibe_diff.generate_summary(session.get_all_findings())
        print("=" * 60)
        print("HUMAN APPROVAL REQUIRED")
        print("=" * 60)
        print(summary)
        print(f"\nTrust Score: {session.trust_score:.2f}")
        print("\nApprove? (y/N): ", end="", flush=True)
        answer = self._read_input().lower()
        if not answer:
            return False
        if answer in YES_ANSWERS:
            return True
        if answer in NO_ANSWERS:
            return False
        # Default to no for any unexpected input
        return False
