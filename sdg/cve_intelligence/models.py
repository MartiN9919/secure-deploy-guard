""""CVE Intelligence Gathering module for Secure Deploy Guard.

Implements the CVE Intelligence Gathering skill using authoritative sources
(NVD, MITRE, OSV) with fallback strategies. No web_search tool required;
uses direct HTTP APIs via httpx.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class Completeness(str, Enum):
    COMPLETE = "COMPLETE"
    MOSTLY_COMPLETE = "MOSTLY_COMPLETE"
    PARTIAL = "PARTIAL"
    MINIMAL = "MINIMAL"


@dataclass
class AffectedPackage:
    name: str
    ecosystem: str = ""
    vulnerable_versions: str = ""
    fixed_version: str = ""
    vulnerable_functions: list[str] = field(default_factory=list)


@dataclass
class CVSS:
    score: Optional[float] = None
    vector: str = ""
    version: str = ""


@dataclass
class InformationSource:
    type: str
    verified: bool
    url: str


@dataclass
class CVEProfile:
    cve_id: str
    aliases: list[str] = field(default_factory=list)
    severity: Severity = Severity.UNKNOWN
    cvss: CVSS = field(default_factory=CVSS)
    affected_packages: list[AffectedPackage] = field(default_factory=list)
    vulnerability_type: str = ""
    cwe_id: str = ""
    attack_vector: str = ""
    description: str = ""
    impact_confidentiality: str = ""
    impact_integrity: str = ""
    impact_availability: str = ""
    remediation_action: str = ""
    workarounds: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    sources: list[InformationSource] = field(default_factory=list)
    completeness: Completeness = Completeness.MINIMAL
    data_quality: str = "LOW"
    gaps: list[str] = field(default_factory=list)
    user_provided: bool = False

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "aliases": self.aliases,
            "severity": self.severity.value,
            "cvss": {
                "score": self.cvss.score,
                "vector": self.cvss.vector,
                "version": self.cvss.version,
            },
            "affected_packages": [
                {
                    "name": p.name,
                    "ecosystem": p.ecosystem,
                    "vulnerable_versions": p.vulnerable_versions,
                    "fixed_version": p.fixed_version,
                    "vulnerable_functions": p.vulnerable_functions,
                }
                for p in self.affected_packages
            ],
            "vulnerability_type": self.vulnerability_type,
            "cwe_id": self.cwe_id,
            "attack_vector": self.attack_vector,
            "description": self.description,
            "impact": {
                "confidentiality": self.impact_confidentiality,
                "integrity": self.impact_integrity,
                "availability": self.impact_availability,
            },
            "remediation": {
                "action": self.remediation_action,
                "workarounds": self.workarounds,
            },
            "references": self.references,
            "sources": [{"type": s.type, "verified": s.verified, "url": s.url} for s in self.sources],
            "completeness": self.completeness.value,
            "data_quality": self.data_quality,
            "gaps": self.gaps,
            "user_provided": self.user_provided,
        }
