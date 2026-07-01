import pytest
from sdg.cve_intelligence.gatherer import CVEIntelligenceGatherer
from sdg.cve_intelligence.sources import validate_cve_id


class TestCVEValidation:
    def test_valid_cve(self):
        assert validate_cve_id("CVE-2023-1234")

    def test_invalid_cve(self):
        assert not validate_cve_id("CVE-2023")
        assert not validate_cve_id("2023-1234")


class TestCVEGathererOffline:
    def test_gatherer_raises_on_invalid_format(self):
        g = CVEIntelligenceGatherer()
        with pytest.raises(ValueError):
            g.gather("INVALID")

    def test_gatherer_returns_profile_even_when_sources_fail(self, monkeypatch):
        g = CVEIntelligenceGatherer()

        def _failing_fetch(*args, **kwargs):
            return None

        for source in g.sources:
            source.fetch = _failing_fetch

        profile = g.gather("CVE-2023-1234")
        assert profile.cve_id == "CVE-2023-1234"
        assert profile.completeness.value == "MINIMAL"


class TestCVEProfile:
    def test_to_dict(self):
        from sdg.cve_intelligence.models import CVEProfile
        profile = CVEProfile(cve_id="CVE-2023-1234")
        d = profile.to_dict()
        assert d["cve_id"] == "CVE-2023-1234"
        assert "severity" in d
