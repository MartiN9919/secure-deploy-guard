import tempfile
from pathlib import Path
from sdg.utils.patterns import scan_with_patterns, EXCLUDED_DIRS, PATTERNS
from sdg.utils.llm import query_llm


class TestPatterns:
    def test_excluded_dirs(self):
        assert ".venv" in EXCLUDED_DIRS
        assert ".git" in EXCLUDED_DIRS

    def test_sql_injection_pattern(self):
        findings = scan_with_patterns("test.py", 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)')
        assert any(f.category.value == "sql_injection" for f in findings)

    def test_hardcoded_secret_pattern(self):
        findings = scan_with_patterns("test.py", 'API_KEY = "sk-1234567890123456"')
        assert any(f.category.value == "hardcoded_secret" for f in findings)

    def test_command_injection_pattern(self):
        findings = scan_with_patterns("test.py", 'os.system("rm -rf " + path)')
        assert any(f.category.value == "command_injection" for f in findings)

    def test_clean_code_no_findings(self):
        findings = scan_with_patterns("test.py", "x = 1 + 2\nprint(x)")
        assert findings == []

    def test_excluded_dir_skipped(self):
        findings = scan_with_patterns("/project/.venv/lib/test.py", "password = 'secret'")
        assert findings == []

    def test_non_matching_extension(self):
        findings = scan_with_patterns("test.md", "execute('SELECT *')")
        assert findings == []

    def test_c_safe_functions(self):
        findings = scan_with_patterns("test.c", "strcpy(dest, src);")
        assert any(f.category.value == "buffer_overflow" for f in findings)


class TestLLM:
    def test_query_no_api_key(self):
        result = query_llm("test", {})
        assert "no API key" in result
