from sdg.orchestrator.session import Session
from sdg.models import ScanTarget, Finding, Severity, ScanCategory, ScanReport


class TestSession:
    def test_session_creation(self):
        t = ScanTarget(path=".")
        s = Session(t, {})
        assert s.session_id is not None
        assert s.target == t
        assert s.trust_score == 1.0
        assert not s.approved

    def test_add_result(self):
        s = Session(ScanTarget(path="."), {})
        r = ScanReport(target=ScanTarget(path="."))
        r.add_finding(Finding(severity=Severity.LOW, category=ScanCategory.CODE_QUALITY, message="ok", file_path="x.py"))
        s.add_result("sast", r)
        assert len(s.agent_results) == 1

    def test_get_all_findings(self):
        s = Session(ScanTarget(path="."), {})
        r1 = ScanReport(target=ScanTarget(path="."))
        r1.add_finding(Finding(severity=Severity.HIGH, category=ScanCategory.XSS, message="xss1", file_path="a.py"))
        r2 = ScanReport(target=ScanTarget(path="."))
        r2.add_finding(Finding(severity=Severity.CRITICAL, category=ScanCategory.SQL_INJECTION, message="sqli", file_path="b.py"))
        s.add_result("sast", r1)
        s.add_result("sca", r2)
        findings = s.get_all_findings()
        assert len(findings) == 2

    def test_summary(self):
        s = Session(ScanTarget(path="."), {})
        r = ScanReport(target=ScanTarget(path="."))
        r.add_finding(Finding(severity=Severity.CRITICAL, category=ScanCategory.SQL_INJECTION, message="a", file_path="a.py"))
        r.add_finding(Finding(severity=Severity.HIGH, category=ScanCategory.XSS, message="b", file_path="b.py"))
        s.add_result("sast", r)
        summary = s.summary()
        assert summary["total_findings"] == 2
        assert summary["by_severity"]["critical"] == 1
        assert summary["by_severity"]["high"] == 1
