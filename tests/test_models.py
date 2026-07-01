from sdg.models import Finding, Severity, ScanCategory, ScanTarget, ScanReport


class TestModels:
    def test_finding_creation(self):
        f = Finding(severity=Severity.CRITICAL, category=ScanCategory.SQL_INJECTION, message="test", file_path="test.py", line_number=10)
        assert f.severity == Severity.CRITICAL
        assert f.category == ScanCategory.SQL_INJECTION
        assert f.line_number == 10

    def test_scan_target_defaults(self):
        t = ScanTarget(path=".")
        assert t.path == "."
        assert t.rules == []

    def test_scan_report_add_finding(self):
        r = ScanReport(target=ScanTarget(path="."))
        f = Finding(severity=Severity.HIGH, category=ScanCategory.XSS, message="xss", file_path="x.html")
        r.add_finding(f)
        assert len(r.findings) == 1

    def test_scan_report_by_severity(self):
        r = ScanReport(target=ScanTarget(path="."))
        r.add_finding(Finding(severity=Severity.CRITICAL, category=ScanCategory.SQL_INJECTION, message="a", file_path="a.py"))
        r.add_finding(Finding(severity=Severity.HIGH, category=ScanCategory.XSS, message="b", file_path="b.py"))
        r.add_finding(Finding(severity=Severity.CRITICAL, category=ScanCategory.COMMAND_INJECTION, message="c", file_path="c.py"))
        by = r.by_severity()
        assert len(by[Severity.CRITICAL]) == 2
        assert len(by[Severity.HIGH]) == 1

    def test_scan_report_passed_high(self):
        r = ScanReport(target=ScanTarget(path="."))
        r.add_finding(Finding(severity=Severity.HIGH, category=ScanCategory.XSS, message="a", file_path="a.py"))
        assert r.passed()

    def test_scan_report_passed_clean(self):
        r = ScanReport(target=ScanTarget(path="."))
        assert r.passed()
