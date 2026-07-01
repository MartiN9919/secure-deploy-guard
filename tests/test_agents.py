from pathlib import Path
import tempfile
from sdg.agents.sast_agent import SASTAgent
from sdg.agents.sca_agent import SCAAgent
from sdg.agents.config_agent import ConfigAgent
from sdg.models import ScanTarget


class TestSASTAgent:
    def setup_method(self):
        self.agent = SASTAgent({"auto_approve": True})

    def test_execute_empty_dir(self, tmp_path: Path):
        report = self.agent.execute(ScanTarget(path=str(tmp_path)))
        assert report.findings == []

    def test_execute_with_vuln(self, tmp_path: Path):
        f = tmp_path / "vuln.py"
        f.write_text("password = 'secret123'\nos.system('rm -rf /')")
        report = self.agent.execute(ScanTarget(path=str(tmp_path)))
        assert len(report.findings) > 0


class TestSCAAgent:
    def setup_method(self):
        self.agent = SCAAgent({"auto_approve": True})

    def test_no_requirements(self, tmp_path: Path):
        report = self.agent.execute(ScanTarget(path=str(tmp_path)))
        assert any("No requirements.txt" in f.message for f in report.findings)

    def test_vulnerable_dep(self, tmp_path: Path):
        (tmp_path / "requirements.txt").write_text("django==3.2.0\n")
        report = self.agent.execute(ScanTarget(path=str(tmp_path)))
        assert any("CVE" in f.message for f in report.findings)

    def test_clean_deps(self, tmp_path: Path):
        (tmp_path / "requirements.txt").write_text("django==5.0.0\n")
        report = self.agent.execute(ScanTarget(path=str(tmp_path)))
        assert not any("CVE" in f.message for f in report.findings)


class TestConfigAgent:
    def setup_method(self):
        self.agent = ConfigAgent({"auto_approve": True})

    def test_no_dockerfile(self, tmp_path: Path):
        report = self.agent.execute(ScanTarget(path=str(tmp_path)))
        assert report.findings == []

    def test_dockerfile_no_user(self, tmp_path: Path):
        (tmp_path / "Dockerfile").write_text("FROM python:3.12\nRUN pip install requests\n")
        report = self.agent.execute(ScanTarget(path=str(tmp_path)))
        assert any("USER" in f.message for f in report.findings)
