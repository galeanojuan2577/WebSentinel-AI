from __future__ import annotations

import asyncio
from urllib.parse import urlparse

import httpx

from src.scanner.checks.base import BaseCheck
from src.scanner.models import CheckResult, Severity

COMMON_WEB_PORTS = [
    80, 443, 8080, 8443, 3000, 5000, 8000,
    8008, 8888, 9000, 9090, 9443, 10443,
]

PORT_SERVICES = {
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    3000: "Dev Server",
    5000: "Flask/Dev",
    8000: "Dev Server",
    8008: "HTTP-Alt",
    8888: "HTTP-Alt",
    9000: "Dev Server",
    9090: "Admin Panel",
    9443: "HTTPS-Alt",
    10443: "HTTPS-Alt",
}


class PortsCheck(BaseCheck):
    name = "open_ports"
    description = "Scans for open web ports beyond the standard 80/443"

    async def run(self, url: str, client: httpx.AsyncClient) -> list[CheckResult]:
        results: list[CheckResult] = []
        hostname = urlparse(url).hostname

        if not hostname:
            return [CheckResult(
                name="Invalid Hostname",
                description=f"No se pudo extraer el hostname de la URL: {url}",
                severity=Severity.INFO,
                url=url,
                remediation="Verificar que la URL sea válida.",
            )]

        async def check_port(port: int) -> tuple[int, bool]:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(hostname, port),
                    timeout=3,
                )
                writer.close()
                return port, True
            except (OSError, asyncio.TimeoutError):
                return port, False

        tasks = [check_port(p) for p in COMMON_WEB_PORTS]
        results_list = await asyncio.gather(*tasks)

        open_ports = [(port, PORT_SERVICES.get(port, "Unknown")) for port, is_open in results_list if is_open]

        standard_ports = {80, 443}
        extra_ports = [(p, s) for p, s in open_ports if p not in standard_ports]

        if extra_ports:
            for port, service in extra_ports:
                results.append(CheckResult(
                    name=f"Open Port: {port} ({service})",
                    description=f"El puerto {port} ({service}) está abierto en {hostname}. "
                                "Puertos adicionales incrementan la superficie de ataque.",
                    severity=Severity.MEDIUM,
                    url=f"{hostname}:{port}",
                    evidence=f"Port: {port}, Service: {service}",
                    remediation="1. Cerrar puertos no necesarios en el firewall.\n"
                                "2. Si el servicio es necesario, asegurarse de que esté correctamente configurado.\n"
                                "3. Usar autenticación y cifrado en todos los servicios expuestos.",
                    references=["https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/"],
                ))
        elif len(open_ports) == 0:
            results.append(CheckResult(
                name="No Open Web Ports",
                description=f"No se detectaron puertos web abiertos en {hostname}. Verifica la conectividad.",
                severity=Severity.INFO,
                url=url,
                remediation="Verificar que el servidor esté funcionando y sea accesible.",
            ))
        else:
            results.append(CheckResult(
                name="Standard Ports Only",
                description=f"Solo los puertos estándar (80, 443) están abiertos en {hostname}.",
                severity=Severity.INFO,
                url=url,
                remediation="N/A — solo puertos estándar expuestos.",
            ))

        return results
