from __future__ import annotations
from typing import Any
from sdg.models import Finding

class GreenTeam:
    def __init__(self, config: dict[str, Any]):
        self.config = config

    def generate_fix(self, finding: Finding) -> str | None:
        fixes = {
            "sql_injection": "Use parameterized query: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            "command_injection": "Use subprocess.run with list: subprocess.run(['ls', '-la'], shell=False)",
            "hardcoded_secret": "Move to env var: import os; API_KEY = os.getenv('API_KEY')",
        }
        return fixes.get(finding.category.value)

    def auto_fix(self, findings: list[Finding]) -> list[dict]:
        return [{"file": f.file_path, "line": f.line_number, "finding": f.message, "suggestion": self.generate_fix(f)} for f in findings if self.generate_fix(f)]
