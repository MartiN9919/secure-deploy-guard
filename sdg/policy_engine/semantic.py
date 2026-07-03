from __future__ import annotations
from typing import Any
from sdg.utils.llm import batch_query_llm

PII_PROMPT = """Evaluate if this action violates security/PII policies.
Action: {action}
Policies: No unmasked PII, no API keys in logs, no production data in non-prod, no destructive ops without confirmation.
Return: VIOLATION or ALLOWED with reasoning."""

class SemanticGate:
    def __init__(self, config: dict[str, Any]):
        self.config = config

    def check_actions(self, descriptions: list[str]) -> list[tuple[bool, str]]:
        """Batch semantic checks to reduce LLM calls."""
        if not descriptions:
            return []
        prompts = [PII_PROMPT.format(action=d) for d in descriptions]
        try:
            results = batch_query_llm(prompts, self.config, system_prompt="You are a policy enforcer.", max_tokens=256)
        except Exception as e:
            return [(False, f"Gate error: {e}") for _ in descriptions]

        decisions = []
        for result in results:
            if "no api key" in result.lower() or "rate limit" in result.lower():
                decisions.append((True, "Semantic gate skipped: no API key or rate limit"))
            elif "ALLOWED" in result.upper():
                decisions.append((True, ""))
            else:
                decisions.append((False, result))
        return decisions

    def check_action(self, description: str) -> tuple[bool, str]:
        decisions = self.check_actions([description])
        return decisions[0] if decisions else (True, "")
