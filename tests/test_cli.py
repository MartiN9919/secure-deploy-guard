import sys
from pathlib import Path
from sdg.cli import cmd_scan


class TestCLIScan:
    def test_cmd_scan_no_error(self, tmp_path: Path, monkeypatch):
        (tmp_path / "test.py").write_text("x = 1\n")
        monkeypatch.setattr("builtins.input", lambda _: "y")
        args = type("Args", (), {"path": str(tmp_path), "role": "developer", "environment": "local", "format": "json", "output": None, "auto_approve": True, "full": False, "sbom": False, "sbom_output": None, "fail_on": None, "func": None})()
        try:
            cmd_scan(args)
        except SystemExit:
            pass
