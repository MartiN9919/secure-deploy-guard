import pytest
from sdg.sandbox.executor import SandboxExecutor


class TestSandboxExecutor:
    def test_runs_allowed_command(self, tmp_path):
        ex = SandboxExecutor(allowed_root=str(tmp_path))
        result = ex.run(["python3", "-c", "print('hello')"])
        assert result.returncode == 0
        assert "hello" in result.stdout

    def test_rejects_string_command(self, tmp_path):
        ex = SandboxExecutor(allowed_root=str(tmp_path))
        with pytest.raises(ValueError):
            ex.run("ls -la")

    def test_rejects_path_outside_root(self, tmp_path):
        ex = SandboxExecutor(allowed_root=str(tmp_path))
        with pytest.raises(PermissionError):
            ex.run(["ls"], cwd="/etc")

    def test_rejects_prefix_attack(self, tmp_path):
        ex = SandboxExecutor(allowed_root=str(tmp_path))
        attacker = str(tmp_path) + "-attacker"
        with pytest.raises(PermissionError):
            ex.run(["ls"], cwd=attacker)
