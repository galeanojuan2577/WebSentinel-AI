from __future__ import annotations

import logging
from typing import Any, Callable, Optional

import httpx

logger = logging.getLogger("websentinel.comprehensive")


async def run_comprehensive_scan(
    url: str,
    include_tech: bool = True,
    include_subdomains: bool = True,
    include_cve: bool = True,
    include_dns: bool = True,
    progress_callback: Optional[Callable] = None,
) -> dict[str, Any]:
    from src.scanner.checks.cve import CVECheck
    from src.scanner.checks.dns import DNSCheck
    from src.scanner.checks.subdomains import SubdomainCheck
    from src.scanner.checks.tech import TechDetectCheck

    base_url = url.rstrip("/")
    results: list = []
    sources: list[str] = []
    timeout = httpx.Timeout(30.0)

    def _client():
        return httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False)

    if include_tech:
        sources.append("technology_detect")
        try:
            async with _client() as client:
                tech = TechDetectCheck()
                tech_results = await tech.run(base_url, client)
                results.extend(tech_results)
        except Exception as e:
            logger.warning(f"Tech detect failed: {e}")
        if progress_callback:
            await progress_callback("tech", "done")

    if include_subdomains:
        sources.append("subdomain_discovery")
        try:
            async with _client() as client:
                sub = SubdomainCheck()
                sub_results = await sub.run(base_url, client)
                results.extend(sub_results)
        except Exception as e:
            logger.warning(f"Subdomain discovery failed: {e}")
        if progress_callback:
            await progress_callback("subdomains", "done")

    if include_cve:
        sources.append("cve_lookup")
        try:
            async with _client() as client:
                cve = CVECheck()
                cve_results = await cve.run(base_url, client)
                results.extend(cve_results)
        except Exception as e:
            logger.warning(f"CVE lookup failed: {e}")
        if progress_callback:
            await progress_callback("cve", "done")

    if include_dns:
        sources.append("dns_enumeration")
        try:
            async with _client() as client:
                dns = DNSCheck()
                dns_results = await dns.run(base_url, client)
                results.extend(dns_results)
        except Exception as e:
            logger.warning(f"DNS enumeration failed: {e}")
        if progress_callback:
            await progress_callback("dns", "done")

    return {
        "target": url,
        "sources": sources,
        "findings": [r.model_dump(mode="json") for r in results],
        "total_findings": len(results),
    }
