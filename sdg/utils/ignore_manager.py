from __future__ import annotations
import hashlib
import json
import re
from pathlib import Path
from typing import Any


class IgnoreManager:
    """Manages inline and baseline-based suppression of findings.

    Inline suppression:
        password = 'test123'  # sdg-ignore: hardcoded_secret

    Baseline file (.sdg-ignore or sdg-baseline.json):
        JSON list of finding fingerprints.
    """

    def __init__(self, baseline_path: str | Path | None = None):
        self.baseline_path = Path(baseline_path) if baseline_path else None
        self.baseline_fingerprints: set[str] = set()
        if self.baseline_path and self.baseline_path.exists():
            try:
                data = json.loads(self.baseline_path.read_text())
                if isinstance(data, list):
                    self.baseline_fingerprints = {str(item) for item in data}
            except Exception:
                self.baseline_fingerprints = set()

    @staticmethod
    def _fingerprint(finding: Any) -> str:
        """Create a stable fingerprint for a finding object."""
        file_path = getattr(finding, "file_path", "") or ""
        line_number = getattr(finding, "line_number", 0) or 0
        category = getattr(finding, "category", "")
        category = category.value if hasattr(category, "value") else str(category)
        snippet = getattr(finding, "snippet", "") or getattr(finding, "message", "") or ""
        source = f"{file_path}:{line_number}:{category}:{snippet}".encode("utf-8")
        return hashlib.sha256(source).hexdigest()[:16]

    @staticmethod
    def _line_has_ignore(line: str, rule_id: str) -> bool:
        match = re.search(r"#\s*sdg-ignore:\s*([\w_,\- ]+)", line)
        if not match:
            match = re.search(r"//\s*sdg-ignore:\s*([\w_,\- ]+)", line)
        if not match:
            return False
        ignored = {r.strip() for r in match.group(1).split(",")}
        return rule_id in ignored or "*" in ignored

    def is_ignored(self, finding: Any, file_lines: dict[str, list[str]] | None = None) -> bool:
        """Check whether a finding is ignored via baseline or inline comment."""
        if self._fingerprint(finding) in self.baseline_fingerprints:
            return True

        file_path = getattr(finding, "file_path", "") or ""
        line_number = getattr(finding, "line_number", 0)
        category = getattr(finding, "category", "")
        rule_id = category.value if hasattr(category, "value") else str(category)

        if file_path and line_number and file_lines is not None:
            lines = file_lines.get(file_path, [])
            if 1 <= line_number <= len(lines):
                if self._line_has_ignore(lines[line_number - 1], rule_id):
                    return True

        return False

    def filter_findings(self, findings: list[Any]) -> list[Any]:
        """Filter out ignored findings."""
        file_lines: dict[str, list[str]] = {}
        for finding in findings:
            fp = getattr(finding, "file_path", "") or ""
            if fp and fp not in file_lines:
                try:
                    file_lines[fp] = Path(fp).read_text(encoding="utf-8", errors="ignore").splitlines()
                except Exception:
                    file_lines[fp] = []
        return [f for f in findings if not self.is_ignored(f, file_lines)]

    def add_to_baseline(self, findings: list[Any]) -> None:
        """Add finding fingerprints to the baseline file."""
        if not self.baseline_path:
            return
        for f in findings:
            self.baseline_fingerprints.add(self._fingerprint(f))
        self.baseline_path.write_text(json.dumps(sorted(self.baseline_fingerprints), indent=2))

    def save_baseline(self) -> None:
        """Persist current baseline fingerprints."""
        if self.baseline_path:
            self.baseline_path.write_text(json.dumps(sorted(self.baseline_fingerprints), indent=2))
