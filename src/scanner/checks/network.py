from __future__ import annotations

import asyncio
import socket

import httpx

from src.scanner.checks.base import BaseCheck
from src.scanner.models import CheckResult, Severity


class NetworkScanCheck(BaseCheck):
    name = "network_scan"
    description = "Escanea la red local para detectar hosts activos y puertos abiertos"

    async def run(self, target: str, client: httpx.AsyncClient) -> list[CheckResult]:
        results: list[CheckResult] = []

        try:
            active_hosts = await self._scan_network(target)

            if not active_hosts:
                results.append(
                    CheckResult(
                        name="No Active Hosts",
                        description="No se detectaron hosts activos en la red.",
                        severity=Severity.INFO,
                        url=target,
                        remediation="Verificar la conectividad de red.",
                    )
                )
                return results

            for host_info in active_hosts:
                host = host_info["host"]
                open_ports = host_info["open_ports"]

                if open_ports:
                    ports_str = ", ".join(str(p) for p in open_ports[:10])
                    results.append(
                        CheckResult(
                            name=f"Host Activo: {host}",
                            description=f"Host {host} detectado con {len(open_ports)} puertos abiertos: {ports_str}",
                            severity=Severity.MEDIUM if len(open_ports) > 3 else Severity.LOW,
                            url=f"scan://{host}",
                            evidence=f"Puertos: {', '.join(map(str, open_ports))}",
                            remediation="1. Revisar si los servicios expuestos son necesarios.\n2. Configurar firewall para restringir acceso.\n3. Actualizar servicios a su última versión.",
                            references=["https://owasp.org/www-project-web-security-testing-guide/"],
                        )
                    )
        except Exception as exc:
            results.append(
                CheckResult(
                    name="Network Scan Error",
                    description=f"Error durante el escaneo de red: {exc}",
                    severity=Severity.INFO,
                    url=target,
                    remediation="Verificar permisos y conectividad de red.",
                )
            )

        return results

    async def _scan_network(self, target: str) -> list[dict]:
        """Escanea la red del target para encontrar hosts activos."""
        import ipaddress

        try:
            hostname = socket.gethostbyname(target.split("//")[-1].split("/")[0])
            ip = ipaddress.ip_address(hostname)

            if ip.version == 4:
                octets = str(ip).split(".")
                octets[-1] = "0/24"
                network = ".".join(octets[:3]) + ".0/24"
            else:
                network = f"{ip}/{64}"
        except Exception:
            network = "192.168.1.0/24"

        try:
            network_obj = ipaddress.ip_network(network, strict=False)
        except ValueError:
            network_obj = ipaddress.ip_network("192.168.1.0/24", strict=False)

        hosts = []
        tasks = []

        for ip_addr in network_obj.hosts():
            if str(ip_addr).endswith(".0") or str(ip_addr).endswith(".255"):
                continue
            tasks.append(self._check_host(str(ip_addr)))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, result in enumerate(results):
            if isinstance(result, dict) and result.get("open_ports"):
                hosts.append(result)

        return hosts

    async def _check_host(self, host: str) -> dict:
        """Verifica si un host está activo y escanea puertos comunes."""
        common_ports = [
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            139,
            143,
            443,
            445,
            993,
            995,
            1433,
            1521,
            3306,
            3389,
            5432,
            5900,
            8080,
            8443,
        ]
        open_ports = []

        tasks = [self._scan_port(host, port) for port in common_ports]
        results = await asyncio.gather(*tasks)

        open_ports = [port for port, is_open in results if is_open]

        return {"host": host, "open_ports": open_ports}

    async def _scan_port(self, host: str, port: int) -> tuple[int, bool]:
        """Verifica si un puerto está abierto en el host."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=1.0,
            )
            writer.close()
            await writer.wait_closed()
            return port, True
        except (OSError, asyncio.TimeoutError, Exception):
            return port, False
