from __future__ import annotations
import re, os
from sdg.models import Finding, Severity, ScanCategory

from sdg.config import load_config

_config = load_config()
_cfg_scan = _config.get("scanning", {})
EXCLUDED_DIRS = {".venv", "__pycache__", ".git", ".pytest_cache", "node_modules", ".superpowers", ".worktrees"}
EXCLUDED_DIRS.update(set(_cfg_scan.get("excluded_dirs", [])))
EXCLUDED_FILE_PATTERNS = ["*.min.js", "*.min.css"]
EXCLUDED_FILE_PATTERNS.extend(_cfg_scan.get("excluded_file_patterns", []))

def _is_excluded_file(file_path: str) -> bool:
    name = os.path.basename(file_path).lower()
    return any(name.endswith(ext.lstrip("*")) for ext in EXCLUDED_FILE_PATTERNS)

PATTERNS = [
    {"category": ScanCategory.SQL_INJECTION, "severity": Severity.CRITICAL, "name": "SQL Injection via string concat", "pattern": r'execute\s*\(\s*["\'][^"\']*["\']\s*\+', "ext": [".py"], "message": "SQL query built via string concatenation — use parameterized queries", "recommendation": "Use parameterized queries"},
    {"category": ScanCategory.SQL_INJECTION, "severity": Severity.CRITICAL, "name": "SQL Injection via f-string", "pattern": r'execute\s*\(\s*f["\']', "ext": [".py"], "message": "SQL query built via f-string", "recommendation": "Use parameterized queries"},
    {"category": ScanCategory.XSS, "severity": Severity.HIGH, "name": "XSS via HTML concat", "pattern": r'["\']\s*\+\s*[\w_\[\]]+\s*\+', "ext": [".py", ".js", ".html"], "message": "HTML string concatenation may lead to XSS", "recommendation": "Use template engines with auto-escaping"},
    {"category": ScanCategory.XSS, "severity": Severity.CRITICAL, "name": "XSS via innerHTML", "pattern": r'(innerHTML\s*=|mark_safe\s*\()', "ext": [".js", ".py"], "message": "Unsafe HTML assignment", "recommendation": "Use textContent instead of innerHTML"},
    {"category": ScanCategory.PATH_TRAVERSAL, "severity": Severity.HIGH, "name": "Path traversal", "pattern": r'open\s*\(\s*[^)]*os\.path\.join\s*\(\s*[^)]*user', "ext": [".py"], "message": "File access using user-controlled path", "recommendation": "Validate and sanitize user input"},
    {"category": ScanCategory.HARDCODED_SECRET, "severity": Severity.CRITICAL, "name": "Hardcoded secret", "pattern": r'(API_KEY|SECRET|PASSWORD|TOKEN)\s*=\s*["\'][^"\']+["\']', "ext": [".py", ".js", ".yaml", ".yml", ".env"], "message": "Hardcoded credential detected", "recommendation": "Use environment variables"},
    {"category": ScanCategory.COMMAND_INJECTION, "severity": Severity.CRITICAL, "name": "Command injection os.system", "pattern": r'os\.system\s*\(\s*["\'][^"\']*["\']\s*\+', "ext": [".py"], "message": "Command injection via os.system", "recommendation": "Use subprocess.run with list"},
    {"category": ScanCategory.COMMAND_INJECTION, "severity": Severity.CRITICAL, "name": "Command injection shell=True", "pattern": r'subprocess\..*shell\s*=\s*True', "ext": [".py"], "message": "subprocess with shell=True", "recommendation": "Use subprocess.run with list args"},
    {"category": ScanCategory.SSRF, "severity": Severity.HIGH, "name": "SSRF via user URL", "pattern": r'requests\.(get|post|put|delete)\s*\(\s*[^)]*user', "ext": [".py"], "message": "HTTP request to user-controlled URL", "recommendation": "Validate URL against allowlist"},
    {"category": ScanCategory.INSECURE_DESERIALIZATION, "severity": Severity.CRITICAL, "name": "Pickle deserialization", "pattern": r'pickle\.loads?\s*\(', "ext": [".py"], "message": "Unsafe deserialization with pickle", "recommendation": "Use JSON instead of pickle"},
    {"category": ScanCategory.BUFFER_OVERFLOW, "severity": Severity.HIGH, "name": "Unsafe C functions", "pattern": r'(strcpy|strcat|sprintf|gets|scanf)\s*\(', "ext": [".c", ".cpp", ".h"], "message": "Unsafe C function — buffer overflow risk", "recommendation": "Use strncpy, strncat, snprintf"},
]

def _should_scan(file_path: str) -> bool:
    parts = file_path.replace("\\", "/").split("/")
    if any(p in EXCLUDED_DIRS for p in parts):
        return False
    if _is_excluded_file(file_path):
        return False
    return True

def scan_with_patterns(file_path: str, content: str) -> list[Finding]:
    if not _should_scan(file_path):
        return []
    ext = os.path.splitext(file_path)[1].lower()
    findings = []
    for p in PATTERNS:
        if ext not in p["ext"]:
            continue
        for match in re.finditer(p["pattern"], content, re.IGNORECASE):
            line_num = content[:match.start()].count("\n") + 1
            findings.append(Finding(severity=p["severity"], category=p["category"], message=p["message"], file_path=file_path, line_number=line_num, snippet=match.group(), recommendation=p.get("recommendation")))
    return findings
