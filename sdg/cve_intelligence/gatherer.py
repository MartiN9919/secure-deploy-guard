"""CVE Intelligence Gatherer — orchestrates multiple authoritative sources."""
from __future__ import annotations
from typing import Optional

from sdg.cve_intelligence.models import CVEProfile, Completeness, Severity, InformationSource
from sdg.cve_intelligence.sources import validate_cve_id, NVDSource, MITRESource, OSVSource


class CVEIntelligenceGatherer:
    """Gather comprehensive CVE information from multiple authoritative sources.

    Mirrors the CVE Intelligence Gathering skill from MCP Market, but uses direct
    HTTP APIs instead of a web_search tool.
    """

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self.sources = [NVDSource(), OSVSource(), MITRESource()]

    def gather(self, cve_id: str, offline_profile: Optional[CVEProfile] = None) -> CVEProfile:
        if not validate_cve_id(cve_id):
            raise ValueError(f"Invalid CVE format. Expected CVE-YYYY-NNNNN, got: {cve_id}")

        profile = CVEProfile(cve_id=cve_id)
        gathered_sources: list[InformationSource] = []

        for source in self.sources:
            try:
                fetched = source.fetch(cve_id, timeout=self.timeout)
                if fetched:
                    profile = self._merge(profile, fetched)
                    gathered_sources.extend(fetched.sources)
            except Exception:
                continue

        if offline_profile:
            profile = self._merge(profile, offline_profile)
            profile.user_provided = True

        if gathered_sources:
            profile.sources = gathered_sources

        profile.completeness = self._assess_completeness(profile)
        profile.data_quality = self._assess_quality(profile)
        profile.gaps = self._identify_gaps(profile)
        return profile

    def _merge(self, base: CVEProfile, other: CVEProfile) -> CVEProfile:
        if other.description:
            base.description = other.description
        if other.severity != Severity.UNKNOWN:
            base.severity = other.severity
        if other.cvss.score is not None:
            base.cvss = other.cvss
        if other.cwe_id:
            base.cwe_id = other.cwe_id
        if other.affected_packages:
            base.affected_packages = other.affected_packages
        if other.references:
            base.references = list(dict.fromkeys(base.references + other.references))
        if other.aliases:
            base.aliases = list(dict.fromkeys(base.aliases + other.aliases))
        if other.remediation_action:
            base.remediation_action = other.remediation_action
        if other.workarounds:
            base.workarounds = other.workarounds
        base.sources.extend(other.sources)
        return base

    def _assess_completeness(self, profile: CVEProfile) -> Completeness:
        score = 0
        if profile.description:
            score += 1
        if profile.severity != Severity.UNKNOWN:
            score += 1
        if profile.cvss.score is not None:
            score += 1
        if profile.affected_packages:
            score += 1
        if profile.cwe_id:
            score += 1
        if profile.references:
            score += 1

        if score >= 6:
            return Completeness.COMPLETE
        if score >= 4:
            return Completeness.MOSTLY_COMPLETE
        if score >= 2:
            return Completeness.PARTIAL
        return Completeness.MINIMAL

    def _assess_quality(self, profile: CVEProfile) -> str:
        verified = [s for s in profile.sources if s.verified]
        if profile.user_provided and not verified:
            return "LOW"
        if len(verified) >= 2 and profile.completeness == Completeness.COMPLETE:
            return "HIGH"
        if verified:
            return "MEDIUM"
        return "LOW"

    def _identify_gaps(self, profile: CVEProfile) -> list[str]:
        gaps = []
        if not profile.description:
            gaps.append("Description unavailable")
        if profile.severity == Severity.UNKNOWN:
            gaps.append("Severity unavailable")
        if profile.cvss.score is None:
            gaps.append("CVSS score unavailable")
        if not profile.affected_packages:
            gaps.append("Affected packages unavailable")
        if not profile.cwe_id:
            gaps.append("CWE unavailable")
        return gaps
