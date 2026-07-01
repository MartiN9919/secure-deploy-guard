from __future__ import annotations
import json, re
from typing import Any
from sdg.models import ScanTarget
from sdg.orchestrator.session import Session
from sdg.utils.llm import query_llm

class LLMJudge:
    def __init__(self, config: dict[str, Any]):
        self.config = config

    def evaluate(self, target: ScanTarget, session: Session) -> dict:
        findings = session.get_all_findings()
        prompt = f"""Evaluate this security scan. Target: {target.path}. Findings: {len(findings)} total.
Critical: {sum(1 for f in findings if f.severity.value == 'critical')}
High: {sum(1 for f in findings if f.severity.value == 'high')}
Top: {chr(10).join(f'- [{f.severity.value}] {f.category.value}: {f.message}' for f in findings[:5])}

Score 1-5 (1=clean, 5=critical). Return JSON: {{"score": int, "quality": str, "recommendation": str}}"""
        try:
            result = query_llm(
                prompt,
                self.config,
                system_prompt="You are a security judge. Return only valid JSON.",
                max_tokens=512,
                response_format={"type": "json_object"},
            )
            if "no api key" in result.lower():
                return {"score": 3, "quality": "judge skipped: no API key", "recommendation": ""}
            parsed = json.loads(result)
            return {
                "score": int(parsed.get("score", 3)),
                "quality": str(parsed.get("quality", "")),
                "recommendation": str(parsed.get("recommendation", "")),
            }
        except Exception as e:
            return {"score": 3, "quality": f"judge error: {e}", "recommendation": ""}
