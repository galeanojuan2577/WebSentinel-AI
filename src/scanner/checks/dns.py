from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any

import httpx

from src.scanner.checks.base import BaseCheck
from src.scanner.models import CheckResult, Severity

logger = logging.getLogger("websentinel.dns")


class DNSCheck(BaseCheck):
    name = "dns_enumeration"
    description = "Resuelve registros DNS básicos (A, AAAA, MX, NS, TXT) — requiere dnspython para registros avanzados"

    def __init__(self):
        self._has_dnspython: bool = False
        try:
            import dns.resolver  # noqa: F401

            self._has_dnspython = True
        except ImportError:
            pass

    async def run(self, url: str, client: httpx.AsyncClient) -> list[CheckResult]:
        results: list[CheckResult] = []
        domain = self._extract_domain(url)
        if not domain:
            return results

        a_records = await self._resolve_a(domain)
        if a_records:
            results.append(
                CheckResult(
                    name=f"DNS A: {domain}",
                    description=f"Registro A encontrado: {', '.join(a_records[:3])}.",
                    severity=Severity.INFO,
                    url=f"dns://{domain}",
                    evidence=f"Domain: {domain}\nA records: {', '.join(a_records[:5])}",
                    remediation="No requiere acción. Registro DNS estándar.",
                    references=[],
                )
            )

        if self._has_dnspython:
            advanced = await self._resolve_advanced(domain)
            for rectype, values in advanced.items():
                if not values:
                    continue
                sensitive = rectype in ("MX", "NS", "TXT")
                results.append(
                    CheckResult(
                        name=f"DNS {rectype}: {domain}",
                        description=(
                            f"Registro {rectype} encontrado. "
                            + (
                                "Puede exponer información de infraestructura de correo o nombres."
                                if sensitive
                                else "Registro DNS estándar."
                            )
                        ),
                        severity=Severity.INFO,
                        url=f"dns://{domain}",
                        evidence=f"Record type: {rectype}\nValues:\n" + "\n".join(values[:3]),
                        remediation=(
                            "Evaluar si los registros MX/NS deben ser públicos u ocultos tras split-horizon DNS."
                            if sensitive
                            else "No requiere acción."
                        ),
                        references=[],
                    )
                )

        if not results:
            results.append(
                CheckResult(
                    name=f"DNS Resolution: {domain}",
                    description=f"No se pudieron resolver registros DNS para {domain}. El dominio no es accesible o no existe.",
                    severity=Severity.INFO,
                    url=f"dns://{domain}",
                    evidence=f"Domain: {domain}",
                    remediation="Verificar que el dominio esté correctamente configurado en el DNS.",
                    references=[],
                )
            )

        return results

    def _extract_domain(self, url: str) -> str:
        url = url.strip()
        if "://" in url:
            url = url.split("://", 1)[1]
        return url.split("/")[0].split(":")[0]

    async def _resolve_a(self, domain: str) -> list[str]:
        try:
            addrs = await asyncio.get_event_loop().run_in_executor(
                None, lambda: socket.getaddrinfo(domain, 80, socket.AF_INET)
            )
            return list(set(str(addr[4][0]) for addr in addrs))
        except socket.gaierror:
            return []
        except Exception as e:
            logger.debug(f"A record lookup failed for {domain}: {e}")
            return []

    async def _resolve_advanced(self, domain: str) -> dict[str, list[str]]:
        import dns.resolver

        result = {}
        for rectype in ("MX", "NS", "TXT", "AAAA", "CNAME"):
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5.0
                resolver.lifetime = 10.0
                qtype = getattr(dns.rdatatype, rectype, dns.rdatatype.A)
                answers: Any = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda rt=qtype: resolver.resolve(domain, rt),  # type: ignore[misc]
                )
                result[rectype] = [str(r) for r in answers[:5]]
            except Exception:
                result[rectype] = []
        return result
