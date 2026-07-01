from sdg.evaluation.trust_score import TrustScoreCalculator
from sdg.evaluation.report import ReportGenerator
from sdg.orchestrator.session import Session
from sdg.models import ScanTarget, Finding, Severity, ScanCategory


class TestTrustScore:
    def setup_method(self):
        self.calc = TrustScoreCalculator()

    def test_clean_score(self):
        assert self.calc.calculate([]) == 1.0

    def test_critical_deduction(self):
        findings = [Finding(severity=Severity.CRITICAL, category=ScanCategory.SQL_INJECTION, message="a", file_path="a.py")]
        assert self.calc.calculate(findings) == 0.7

    def test_high_deduction(self):
        findings = [Finding(severity=Severity.HIGH, category=ScanCategory.XSS, message="a", file_path="a.py")]
        assert self.calc.calculate(findings) == 0.85

    def test_medium_deduction(self):
        findings = [Finding(severity=Severity.MEDIUM, category=ScanCategory.CODE_QUALITY, message="a", file_path="a.py")]
        assert self.calc.calculate(findings) == 0.95

    def test_low_deduction(self):
        findings = [Finding(severity=Severity.LOW, category=ScanCategory.CODE_QUALITY, message="a", file_path="a.py")]
        assert self.calc.calculate(findings) == 0.99

    def test_multiple_findings(self):
        findings = [
            Finding(severity=Severity.CRITICAL, category=ScanCategory.SQL_INJECTION, message="a", file_path="a.py"),
            Finding(severity=Severity.HIGH, category=ScanCategory.XSS, message="b", file_path="b.py"),
            Finding(severity=Severity.MEDIUM, category=ScanCategory.DEPENDENCY_VULN, message="c", file_path="c.py"),
        ]
        assert self.calc.calculate(findings) == 0.5

    def test_clamped_to_zero(self):
        many_findings = [Finding(severity=Severity.CRITICAL, category=ScanCategory.SQL_INJECTION, message="a", file_path=f"{i}.py") for i in range(10)]
        assert self.calc.calculate(many_findings) == 0.0


class TestReportGenerator:
    def setup_method(self):
        self.gen = ReportGenerator()

    def test_generate_empty(self):
        s = Session(ScanTarget(path="."), {})
        r = self.gen.generate(s)
        assert r["trust_score"] == 1.0
        assert r["summary"]["total_findings"] == 0
        assert not r["approved"]

    def test_generate_with_findings(self):
        s = Session(ScanTarget(path="/test"), {})
        from sdg.models import ScanReport
        rep = ScanReport(target=ScanTarget(path="/test"))
        rep.add_finding(Finding(severity=Severity.CRITICAL, category=ScanCategory.SQL_INJECTION, message="vuln", file_path="x.py"))
        s.add_result("sast", rep)
        s.trust_score = 0.7
        r = self.gen.generate(s)
        assert r["summary"]["critical"] == 1

    def test_to_markdown(self):
        s = Session(ScanTarget(path="."), {})
        md = self.gen.to_markdown(s)
        assert "Secure Deploy Guard" in md
        assert "Trust Score" in md
