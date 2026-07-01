from sdg.hitl.vibe_diff import VibeDiff
from sdg.hitl.approval import ApprovalGate
from sdg.models import Finding, Severity, ScanCategory, ScanTarget
from sdg.orchestrator.session import Session


class TestVibeDiff:
    def setup_method(self):
        self.vd = VibeDiff({})

    def test_no_findings(self):
        assert "No security issues" in self.vd.generate_summary([])

    def test_critical_findings(self):
        findings = [Finding(severity=Severity.CRITICAL, category=ScanCategory.SQL_INJECTION, message="SQL injection", file_path="app.py")]
        summary = self.vd.generate_summary(findings)
        assert "critical" in summary.lower()
        assert "SQL injection" in summary


class TestApprovalGate:
    def test_auto_approve(self):
        gate = ApprovalGate({"auto_approve": True})
        s = Session(ScanTarget(path="."), {})
        assert gate.request(s)

    def test_not_auto_approve(self, monkeypatch):
        gate = ApprovalGate({"auto_approve": False})
        s = Session(ScanTarget(path="."), {})
        monkeypatch.setattr("sys.stdin.buffer.readline", lambda: b"y\n")
        assert gate.request(s)

    def test_not_auto_approve_denied(self, monkeypatch):
        gate = ApprovalGate({"auto_approve": False})
        s = Session(ScanTarget(path="."), {})
        monkeypatch.setattr("sys.stdin.buffer.readline", lambda: b"n\n")
        assert not gate.request(s)

    def test_cyrillic_yes(self, monkeypatch):
        gate = ApprovalGate({"auto_approve": False})
        s = Session(ScanTarget(path="."), {})
        monkeypatch.setattr("sys.stdin.buffer.readline", lambda: "да\n".encode("utf-8"))
        assert gate.request(s)
