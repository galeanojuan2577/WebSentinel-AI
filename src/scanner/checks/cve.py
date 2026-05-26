from __future__ import annotations

import logging
from typing import Optional

import httpx

from src.scanner.checks.base import BaseCheck
from src.scanner.models import CheckResult, Severity

logger = logging.getLogger("websentinel.cve")


class CVECheck(BaseCheck):
    name = "cve_lookup"
    description = "Busca CVEs conocidos para tecnologías detectadas en el sitio vía NVD API"

    def __init__(self):
        self.nvd_api = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def run(self, url: str, client: httpx.AsyncClient) -> list[CheckResult]:
        results = []
        try:
            techs = await self._detect_tech(url, client)
            for tech in techs:
                cves = await self._search_cve(tech, client)
                for cve in cves:
                    cvss = self._parse_cvss(cve)
                    results.append(CheckResult(
                        name=f"CVE: {cve['id']} — {tech}",
                        description=cve.get("description", f"Vulnerabilidad publicada relacionada con {tech}."),
                        severity=self._cvss_to_severity(cvss),
                        url=url,
                        evidence=f"Tecnología afectada: {tech} | CVSS v3: {cvss} | Publicado: {cve.get('published', 'N/A')}",
                        remediation=f"Actualizar {tech} a la versión más reciente. Referencia oficial: https://nvd.nist.gov/vuln/detail/{cve['id']}",
                        references=[f"https://nvd.nist.gov/vuln/detail/{cve['id']}"],
                    ))
        except Exception as e:
            logger.warning(f"CVE lookup failed: {e}")

        return results

    async def _detect_tech(self, url: str, client: httpx.AsyncClient) -> list[str]:
        techs = []
        try:
            resp = await client.get(url, timeout=15.0)
            h = resp.headers
            text = resp.text.lower()
            if "server" in h:
                techs.append(h["server"])
            if "x-powered-by" in h:
                techs.append(h["x-powered-by"])
            sigs = {
                "nginx": "nginx", "apache": "Apache", "iis": "IIS",
                "php": "PHP", "django": "Django", "laravel": "Laravel",
                "wordpress": "WordPress", "drupal": "Drupal",
                "express": "Express.js", "flask": "Flask", "rails": "Ruby on Rails",
                "tomcat": "Apache Tomcat", "jetty": "Eclipse Jetty",
            }
            for sig, name in sigs.items():
                if sig in text:
                    techs.append(name)
        except Exception:
            pass
        return list(set(techs))

    async def _search_cve(self, tech: str, client: httpx.AsyncClient) -> list[dict]:
        try:
            kw = tech.lower().split("/")[0].split()[0]
            params = {"keywordSearch": kw, "resultsPerPage": 5}
            resp = await client.get(self.nvd_api, params=params, timeout=20.0)
            if resp.status_code != 200:
                return []
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            result = []
            for v in vulns:
                cve = v.get("cve", {})
                cve_id = cve.get("id", "")
                if not cve_id:
                    continue
                descriptions = cve.get("descriptions", [])
                desc = next(
                    (d["value"] for d in descriptions if d.get("lang") == "en"),
                    descriptions[0]["value"] if descriptions else "No description available.",
                )
                metrics = cve.get("metrics", {})
                cvss_data = (
                    metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                    or metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
                    or {}
                )
                published = cve.get("published", "")[:10]
                result.append({
                    "id": cve_id,
                    "description": desc[:500],
                    "cvss": cvss_data.get("baseScore", "N/A"),
                    "published": published,
                })
            return result
        except Exception as e:
            logger.debug(f"NVD search failed for {tech}: {e}")
            return []

    def _parse_cvss(self, cve: dict) -> float:
        try:
            return float(cve.get("cvss", 0))
        except (ValueError, TypeError):
            return 0.0

    def _cvss_to_severity(self, cvss: float) -> Severity:
        if cvss >= 9.0:
            return Severity.CRITICAL
        if cvss >= 7.0:
            return Severity.HIGH
        if cvss >= 4.0:
            return Severity.MEDIUM
        if cvss > 0.0:
            return Severity.LOW
        return Severity.INFO
