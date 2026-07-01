from __future__ import annotations
from typing import Any
from pathlib import Path

PATTERNS = [
    {"name": "instruction_injection", "patterns": ["ignore previous instructions", "you are now in debug mode", "forget all previous rules", "you are a free agent now"]},
    {"name": "hidden_commands", "patterns": ["<!-- execute:", "<!-- run:", "`rm -rf", "`curl "]},
    {"name": "zero_width_chars", "patterns": ["\u200b", "\u200c", "\u200d", "\ufeff"]},
]

class RedTeam:
    def __init__(self, config: dict[str, Any]):
        self.config = config

    def scan_adversarial(self, content: str) -> list[dict]:
        findings = []
        for cat in PATTERNS:
            for pattern in cat["patterns"]:
                if pattern.lower() in content.lower():
                    findings.append({"type": cat["name"], "pattern": pattern, "severity": "high"})
                    break
        return findings

    def run(self, target_path: str) -> dict:
        path = Path(target_path)
        all_findings = []
        for ext in ("*.py", "*.js", "*.html", "*.md", "*.txt", "*.yaml", "*.yml"):
            for f in path.rglob(ext):
                try:
                    for finding in self.scan_adversarial(f.read_text()):
                        finding["file"] = str(f)
                        all_findings.append(finding)
                except Exception:
                    continue
        return {"agent": "red_team", "findings": all_findings, "summary": {"total": len(all_findings), "types": {c["name"]: sum(1 for f in all_findings if f["type"] == c["name"]) for c in PATTERNS}}}
