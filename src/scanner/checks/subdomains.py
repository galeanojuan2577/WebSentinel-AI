from __future__ import annotations

import asyncio
import logging
import socket
from typing import Optional

import httpx

from src.scanner.checks.base import BaseCheck
from src.scanner.models import CheckResult, Severity

logger = logging.getLogger("websentinel.subdomains")


class SubdomainCheck(BaseCheck):
    name = "subdomain_discovery"
    description = "Descubre subdominios vía crt.sh y verifica resolución DNS antes de reportar"

    COMMON_SUBDOMAINS = [
        "www",
        "mail",
        "admin",
        "api",
        "dev",
        "staging",
        "test",
        "beta",
        "app",
        "portal",
        "login",
        "sso",
        "auth",
        "cdn",
        "blog",
        "shop",
        "docs",
        "help",
        "support",
        "status",
        "git",
        "jenkins",
        "jira",
        "dashboard",
        "console",
        "monitor",
        "backup",
        "vpn",
        "remote",
        "webmail",
        "owa",
        "m",
        "mobile",
        "graphql",
        "ws",
        "socket",
        "static",
        "assets",
        "uploads",
        "analytics",
        "tracking",
        "logs",
    ]

    def __init__(self, wordlist: Optional[list[str]] = None):
        self.wordlist = wordlist or self.COMMON_SUBDOMAINS

    async def run(self, url: str, client: httpx.AsyncClient) -> list[CheckResult]:
        results = []
        domain = self._extract_domain(url)
        if not domain:
            return results

        candidates: dict[str, str] = {}

        try:
            crt = await self._search_crtsh(domain, client)
            candidates.update(crt)
        except Exception as e:
            logger.debug(f"crt.sh failed: {e}")

        if not candidates:
            try:
                brute = await self._brute_verify(domain)
                candidates.update(brute)
            except Exception as e:
                logger.debug(f"Brute force failed: {e}")

        for subdomain, ip in sorted(candidates.items()):
            fqdn = f"{subdomain}.{domain}"
            is_shadow = any(
                k in subdomain
                for k in [
                    "admin",
                    "dev",
                    "staging",
                    "test",
                    "internal",
                    "jenkins",
                    "jira",
                    "dashboard",
                    "console",
                    "phpmyadmin",
                    "backup",
                    "git",
                    "vpn",
                    "remote",
                ]
            )
            results.append(
                CheckResult(
                    name=f"Subdomain: {fqdn}",
                    description=(
                        f"Subdominio verificable: {fqdn} (IP: {ip}). "
                        f"Endpoint no documentado — verificar propiedad y propósito."
                        if is_shadow
                        else f"Subdominio público detectado: {fqdn}."
                    ),
                    severity=Severity.MEDIUM if is_shadow else Severity.INFO,
                    url=f"https://{fqdn}",
                    evidence=f"Subdomain: {fqdn}\nResolved IP: {ip}\n{'Posible shadow resource — requiere investigación manual.' if is_shadow else 'Subdominio activo.'}",
                    remediation=(
                        "1. Verificar si el subdominio está autorizado.\n"
                        "2. Asegurar misma postura de seguridad que el dominio principal.\n"
                        "3. Dar de baja si no está en uso."
                        if is_shadow
                        else "No requiere acción inmediata. Monitorear periódicamente."
                    ),
                    references=["https://crt.sh/"],
                )
            )

        if not results:
            results.append(
                CheckResult(
                    name=f"Subdomain Discovery: {domain}",
                    description=f"No se encontraron subdominios verificables para {domain}.",
                    severity=Severity.INFO,
                    url=url,
                    evidence=f"Domain: {domain}",
                    remediation="Monitoreo periódico recomendado.",
                    references=[],
                )
            )

        return results

    def _extract_domain(self, url: str) -> str:
        url = url.strip()
        if "://" in url:
            url = url.split("://", 1)[1]
        return url.split("/")[0].split(":")[0]

    async def _search_crtsh(self, domain: str, client: httpx.AsyncClient) -> dict[str, str]:
        discovered = {}
        resp = await client.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=20.0,
            headers={"User-Agent": "VulnScout/0.1"},
        )
        if resp.status_code != 200:
            return discovered

        data = resp.json()
        seen = set()
        for entry in data[:200]:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower()
                if sub.endswith(f".{domain}") and sub != f"*.{domain}":
                    subname = sub.replace(f".{domain}", "")
                    if subname and subname not in seen:
                        seen.add(subname)
                        ip = await self._resolve(sub)
                        if ip:
                            discovered[subname] = ip
        return discovered

    async def _brute_verify(self, domain: str) -> dict[str, str]:
        discovered = {}
        sem = asyncio.Semaphore(10)

        async def check(sub: str) -> tuple[str, str | None]:
            async with sem:
                fqdn = f"{sub}.{domain}"
                ip = await self._resolve(fqdn)
                return sub, ip

        tasks = [check(sub) for sub in self.wordlist]
        for coro in asyncio.as_completed(tasks):
            sub, ip = await coro
            if ip:
                discovered[sub] = ip

        return discovered

    async def _resolve(self, hostname: str) -> str | None:
        try:
            addrs = await asyncio.get_event_loop().run_in_executor(
                None, lambda: socket.getaddrinfo(hostname, 80, socket.AF_INET)
            )
            if addrs:
                return addrs[0][4][0]
        except (socket.gaierror, OSError):
            pass
        return None
