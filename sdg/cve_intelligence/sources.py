from __future__ import annotations
import re
from typing import Optional

from sdg.cve_intelligence.models import CVEProfile, InformationSource, AffectedPackage, CVSS, Severity, Completeness


CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


def validate_cve_id(cve_id: str) -> bool:
    return bool(CVE_PATTERN.match(cve_id))


def extract_year(cve_id: str) -> str:
    return cve_id.split("-")[1]


def extract_number(cve_id: str) -> str:
    return cve_id.split("-")[2]


class NVDSource:
    name = "NVD"
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def fetch(self, cve_id: str, timeout: float = 10.0) -> Optional[CVEProfile]:
        import httpx
        try:
            resp = httpx.get(f"{self.base_url}?cveId={cve_id}", timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            return self._parse(data, cve_id)
        except Exception:
            return None

    def _parse(self, data: dict, cve_id: str) -> Optional[CVEProfile]:
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None
        item = vulnerabilities[0].get("cve", {})
        descriptions = item.get("descriptions", [])
        description = ""
        for d in descriptions:
            if d.get("lang") == "en":
                description = d.get("value", "")
                break

        metrics = item.get("metrics", {})
        cvss = CVSS()
        for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if version in metrics and metrics[version]:
                data_cvss = metrics[version][0].get("cvssData", {})
                cvss.score = data_cvss.get("baseScore")
                cvss.vector = data_cvss.get("vectorString", "")
                cvss.version = data_cvss.get("version", "")
                break

        weaknesses = item.get("weaknesses", [])
        cwe_id = ""
        if weaknesses:
            descs = weaknesses[0].get("description", [])
            for d in descs:
                if d.get("lang") == "en" and d.get("value", "").startswith("CWE-"):
                    cwe_id = d["value"]
                    break

        configurations = item.get("configurations", [])
        affected: list[AffectedPackage] = []
        for cfg in configurations:
            for node in cfg.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    criteria = cpe.get("criteria", "")
                    if criteria.startswith("cpe:2.3:a:"):
                        parts = criteria.split(":")
                        if len(parts) >= 5:
                            vendor = parts[3]
                            product = parts[4]
                            affected.append(AffectedPackage(name=f"{vendor}/{product}"))

        severity = Severity.UNKNOWN
        if cvss.score is not None:
            if cvss.score >= 9.0:
                severity = Severity.CRITICAL
            elif cvss.score >= 7.0:
                severity = Severity.HIGH
            elif cvss.score >= 4.0:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

        profile = CVEProfile(
            cve_id=cve_id,
            description=description,
            cvss=cvss,
            severity=severity,
            cwe_id=cwe_id,
            affected_packages=affected,
            sources=[InformationSource(type="NVD", verified=True, url=f"https://nvd.nist.gov/vuln/detail/{cve_id}")],
            completeness=Completeness.MOSTLY_COMPLETE,
            data_quality="HIGH",
        )
        return profile


class MITRESource:
    name = "MITRE"
    base_url = "https://cveawg.mitre.org/api/cve"

    def fetch(self, cve_id: str, timeout: float = 10.0) -> Optional[CVEProfile]:
        import httpx
        try:
            resp = httpx.get(f"{self.base_url}/{cve_id}", timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            return self._parse(data, cve_id)
        except Exception:
            return None

    def _parse(self, data: dict, cve_id: str) -> Optional[CVEProfile]:
        cna = data.get("containers", {}).get("cna", {})
        descriptions = cna.get("descriptions", [])
        description = ""
        for d in descriptions:
            if d.get("lang") == "en":
                description = d.get("value", "")
                break
        refs = [r.get("url", "") for r in cna.get("references", []) if r.get("url")]
        return CVEProfile(
            cve_id=cve_id,
            description=description,
            references=refs,
            sources=[InformationSource(type="MITRE", verified=True, url=f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}")],
            completeness=Completeness.PARTIAL,
            data_quality="MEDIUM",
        )


class OSVSource:
    name = "OSV"
    base_url = "https://api.osv.dev/v1/vulns"

    def fetch(self, cve_id: str, timeout: float = 10.0) -> Optional[CVEProfile]:
        import httpx
        try:
            resp = httpx.get(f"{self.base_url}/{cve_id}", timeout=timeout)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json()
            return self._parse(data, cve_id)
        except Exception:
            return None

    def _parse(self, data: dict, cve_id: str) -> Optional[CVEProfile]:
        aliases = data.get("aliases", [])
        details = data.get("details", "")
        summary = data.get("summary", "")
        description = details or summary

        affected = data.get("affected", [])
        packages: list[AffectedPackage] = []
        for aff in affected:
            pkg = aff.get("package", {})
            name = pkg.get("name", "")
            ecosystem = pkg.get("ecosystem", "")
            ranges = aff.get("ranges", [])
            fixed = ""
            vulnerable = ""
            for r in ranges:
                for ev in r.get("events", []):
                    if "fixed" in ev:
                        fixed = ev["fixed"]
                    if "introduced" in ev and ev["introduced"] == "0":
                        vulnerable = "all versions before " + fixed if fixed else "unknown"
            packages.append(AffectedPackage(name=name, ecosystem=ecosystem, vulnerable_versions=vulnerable, fixed_version=fixed))

        severity = Severity.UNKNOWN
        severities = data.get("severity", [])
        cvss = CVSS()
        for s in severities:
            if s.get("type") == "CVSS_V3":
                cvss.score = s.get("score")
                cvss.vector = s.get("vector_string", "")
                cvss.version = "3.1"
                break

        if cvss.score is not None:
            if cvss.score >= 9.0:
                severity = Severity.CRITICAL
            elif cvss.score >= 7.0:
                severity = Severity.HIGH
            elif cvss.score >= 4.0:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW

        refs = [r for r in data.get("references", []) if isinstance(r, str)]
        return CVEProfile(
            cve_id=cve_id,
            aliases=aliases,
            description=description,
            severity=severity,
            cvss=cvss,
            affected_packages=packages,
            references=refs,
            sources=[InformationSource(type="OSV", verified=True, url=f"https://osv.dev/vulnerability/{cve_id}")],
            completeness=Completeness.MOSTLY_COMPLETE,
            data_quality="HIGH",
        )
