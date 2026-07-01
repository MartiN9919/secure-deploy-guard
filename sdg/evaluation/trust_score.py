from __future__ import annotations
from sdg.models import Finding, Severity

class TrustScoreCalculator:
    def calculate(self, findings: list[Finding]) -> float:
        score = 1.0
        for f in findings:
            if f.severity == Severity.CRITICAL: score -= 0.3
            elif f.severity == Severity.HIGH: score -= 0.15
            elif f.severity == Severity.MEDIUM: score -= 0.05
            elif f.severity == Severity.LOW: score -= 0.01
        return max(0.0, min(1.0, round(score, 2)))
