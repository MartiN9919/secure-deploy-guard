from __future__ import annotations
from typing import Any
from sdg.utils.llm import query_llm

PII_PROMPT = """Evaluate if this action violates security/PII policies.
Action: {action}
Policies: No unmasked PII, no API keys in logs, no production data in non-prod, no destructive ops without confirmation.
Return: VIOLATION or ALLOWED with reasoning."""

class SemanticGate:
    def __init__(self, config: dict[str, Any]):
        self.config = config
    
    def check_action(self, description: str) -> tuple[bool, str]:
        try:
            result = query_llm(PII_PROMPT.format(action=description), self.config, system_prompt="You are a policy enforcer.", max_tokens=256)
            if "no api key" in result.lower():
                return True, "Semantic gate skipped: no API key configured"
            if "ALLOWED" in result.upper():
                return True, ""
            return False, result
        except Exception as e:
            return False, f"Gate error: {e}"
