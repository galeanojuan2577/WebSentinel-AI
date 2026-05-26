from __future__ import annotations

import asyncio
import logging

import httpx

from src.scanner.checks.base import BaseCheck
from src.scanner.models import CheckResult, Severity

logger = logging.getLogger("websentinel.tech")


class TechDetectCheck(BaseCheck):
    name = "technology_detect"
    description = "Detecta tecnologías del sitio y descubre endpoints comunes con verificación de contenido"

    HEADER_SIGNATURES = {
        "server": {
            "nginx": "Nginx",
            "apache": "Apache HTTP Server",
            "cloudflare": "Cloudflare",
            "iis": "Microsoft IIS",
            "caddy": "Caddy",
            "openresty": "OpenResty",
            "gunicorn": "Gunicorn",
            "uvicorn": "Uvicorn",
        },
        "x-powered-by": {
            "php": "PHP",
            "express": "Express.js",
            "asp.net": "ASP.NET",
            "rails": "Ruby on Rails",
            "django": "Django",
            "flask": "Flask",
            "fastapi": "FastAPI",
            "laravel": "Laravel",
            "symfony": "Symfony",
        },
        "x-generator": {
            "wordpress": "WordPress",
            "drupal": "Drupal",
            "joomla": "Joomla",
        },
    }

    HTML_SIGNATURES = {
        "react": "React",
        "vue": "Vue.js",
        "angular": "Angular",
        "svelte": "Svelte",
        "next.js": "Next.js",
        "nuxt": "Nuxt.js",
        "jquery": "jQuery",
        "bootstrap": "Bootstrap",
        "tailwindcss": "Tailwind CSS",
        "django": "Django",
        "laravel": "Laravel",
        "wordpress": "WordPress",
        "shopify": "Shopify",
        "vite": "Vite",
        "webpack": "Webpack",
    }

    ENDPOINT_PATTERNS = [
        ("/robots.txt", "Robots.txt"),
        ("/sitemap.xml", "Sitemap"),
        ("/.well-known/security.txt", "Security.txt"),
        ("/favicon.ico", "Favicon"),
    ]

    API_PATTERNS = [
        "/api",
        "/api/v1",
        "/api/v2",
        "/graphql",
        "/swagger.json",
        "/api/docs",
        "/docs",
        "/health",
        "/.env",
        "/admin",
    ]

    async def run(self, url: str, client: httpx.AsyncClient) -> list[CheckResult]:
        results = []
        base_url = url.rstrip("/")
        technologies: dict[str, str] = {}

        try:
            resp = await client.get(url, timeout=15.0, follow_redirects=True)
            h = resp.headers
            body = resp.text.lower()

            for header, sigs in self.HEADER_SIGNATURES.items():
                val = h.get(header, "").lower()
                for sig, name in sigs.items():
                    if sig in val:
                        technologies[name] = f"HTTP header: {header}"

            for sig, name in self.HTML_SIGNATURES.items():
                if sig in body:
                    technologies[name] = "HTML/JS detection"

        except Exception as e:
            logger.debug(f"Tech detection HTTP failed: {e}")

        for tech, source in sorted(technologies.items()):
            results.append(
                CheckResult(
                    name=f"Technology: {tech}",
                    description=f"Tecnología detectada en {url} via {source}.",
                    severity=Severity.INFO,
                    url=url,
                    evidence=f"Technology: {tech}\nSource: {source}",
                    remediation=f"Mantener {tech} actualizado siguiendo las mejores prácticas de seguridad.",
                    references=[],
                )
            )

        ep_results = await self._check_endpoints(base_url, client)
        results.extend(ep_results)

        if not technologies and not ep_results:
            results.append(
                CheckResult(
                    name="Technology Detection",
                    description="No se detectaron tecnologías conocidas. El sitio puede usar un stack personalizado o estar protegido por WAF/CDN.",
                    severity=Severity.INFO,
                    url=url,
                    evidence="Ninguna firma reconocida en headers o HTML.",
                    remediation="Verificar tecnologías manualmente.",
                    references=[],
                )
            )

        return results

    async def _check_endpoints(self, base_url: str, client: httpx.AsyncClient) -> list[CheckResult]:
        results = []
        sem = asyncio.Semaphore(5)

        async def check(path: str, desc: str, sensitive: bool = False):
            async with sem:
                try:
                    url = f"{base_url}{path}"
                    resp = await client.get(url, timeout=8.0, follow_redirects=False)
                    if resp.status_code == 404:
                        return None
                    body = resp.text.strip()
                    if not body or len(body) < 10:
                        return None
                    if resp.status_code in (401, 403) and (
                        "unauthorized" in body.lower() or "forbidden" in body.lower() or len(body) < 50
                    ):
                        return None
                    return CheckResult(
                        name=f"Endpoint: {path}",
                        description=(
                            f"Endpoint encontrado: {desc} (HTTP {resp.status_code}). "
                            + (
                                "Posible shadow API — verificar si está documentado y autenticado."
                                if sensitive
                                else "Endpoint público accesible."
                            )
                        ),
                        severity=Severity.MEDIUM if sensitive else Severity.LOW,
                        url=url,
                        evidence=f"Endpoint: {path}\nStatus: {resp.status_code}\nContent-Type: {resp.headers.get('content-type', 'N/A')}\nResponse size: {len(body)} bytes",
                        remediation=(
                            "Asegurar autenticación y rate-limiting. Verificar que no exponga datos sensibles."
                            if sensitive
                            else "Endpoint documentado. Revisar configuración de seguridad periódicamente."
                        ),
                        references=[],
                    )
                except Exception:
                    return None

        tasks = []
        for path, desc in self.ENDPOINT_PATTERNS:
            tasks.append(check(path, desc))
        for path in self.API_PATTERNS:
            tasks.append(check(path, path.split("/")[-1], sensitive=True))

        for coro in asyncio.as_completed(tasks):
            r = await coro
            if r:
                results.append(r)

        return results
