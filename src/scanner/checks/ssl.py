from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime

import httpx

from src.scanner.checks.base import BaseCheck
from src.scanner.models import CheckResult, Severity


def _extract_hostname(url: str) -> str:
    url = url.strip()
    if url.startswith("https://"):
        url = url[8:]
    elif url.startswith("http://"):
        url = url[7:]
    if "/" in url:
        url = url.split("/")[0]
    if ":" in url:
        url = url.split(":")[0]
    return url


class SSLCheck(BaseCheck):
    name = "ssl_tls"
    description = "Analyzes SSL/TLS certificate validity, protocols, and HSTS"

    async def run(self, url: str, client: httpx.AsyncClient) -> list[CheckResult]:
        results: list[CheckResult] = []
        hostname = _extract_hostname(url)
        port = 443

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED

            reader, writer = await asyncio_open_connection(hostname, port, ssl=ctx, server_hostname=hostname)
            sock = writer.transport.get_extra_info("ssl_object")
            cert = sock.getpeercert()

            if not cert:
                return [CheckResult(
                    name="No SSL Certificate",
                    description="El servidor no presentó un certificado SSL.",
                    severity=Severity.HIGH,
                    url=url,
                    remediation="Configurar un certificado SSL/TLS válido emitido por una CA confiable.",
                )]

            not_after_str = cert.get("notAfter", "")
            if not_after_str:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                if not_after < datetime.now():
                    results.append(CheckResult(
                        name="Expired SSL Certificate",
                        description=f"El certificado expiró el {not_after_str}.",
                        severity=Severity.HIGH,
                        url=url,
                        evidence=f"Expired: {not_after_str}",
                        remediation="Renovar el certificado SSL con tu proveedor de CA.",
                        references=["https://letsencrypt.org/"],
                    ))
                elif (not_after - datetime.now()).days < 30:
                    results.append(CheckResult(
                        name="SSL Certificate Expiring Soon",
                        description=f"El certificado expirará el {not_after_str} ({ (not_after - datetime.now()).days } días).",
                        severity=Severity.MEDIUM,
                        url=url,
                        evidence=f"Expires: {not_after_str}",
                        remediation="Renovar el certificado antes de su expiración.",
                    ))

            issuer = dict(x[0] for x in cert.get("issuer", []))
            subject = dict(x[0] for x in cert.get("subject", []))
            cn = subject.get("commonName", "unknown")
            results.append(CheckResult(
                name="SSL Certificate Info",
                description=f"Certificado emitido por: {issuer.get('organizationName', 'Unknown')} | "
                            f"Subject: {cn} | Válido hasta: {not_after_str}",
                severity=Severity.INFO,
                url=url,
                evidence=f"Subject: {cn}, Issuer: {issuer.get('organizationName', 'Unknown')}",
                remediation="N/A — información del certificado.",
            ))

            writer.close()

        except ssl.SSLCertVerificationError as exc:
            results.append(CheckResult(
                name="SSL Certificate Verification Failed",
                description=f"El certificado no pudo ser verificado: {exc}",
                severity=Severity.HIGH,
                url=url,
                evidence=str(exc),
                remediation="Verificar que el certificado sea emitido por una CA confiable y que el hostname coincida.",
            ))
        except (OSError, socket.gaierror) as exc:
            results.append(CheckResult(
                name="SSL Connection Error",
                description=f"No se pudo establecer conexión SSL: {exc}",
                severity=Severity.MEDIUM,
                url=url,
                evidence=str(exc),
                remediation="Verificar que el servidor soporte HTTPS en el puerto 443.",
            ))

        try:
            resp = await client.get(f"https://{hostname}", follow_redirects=True, timeout=10)
            hsts = resp.headers.get("strict-transport-security", "")
            if not hsts:
                results.append(CheckResult(
                    name="Missing HSTS Header",
                    description="No se detectó Strict-Transport-Security. Los navegadores podrían conectar por HTTP en visitas posteriores.",
                    severity=Severity.MEDIUM,
                    url=f"https://{hostname}",
                    remediation="Agregar al servidor web:\n"
                                "Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    references=["https://owasp.org/www-project-secure-headers/#http-strict-transport-security"],
                ))
            else:
                results.append(CheckResult(
                    name="HSTS Header Present",
                    description=f"HSTS configurado: {hsts}",
                    severity=Severity.INFO,
                    url=f"https://{hostname}",
                    evidence=hsts,
                    remediation="N/A — HSTS está correctamente configurado.",
                ))
        except Exception:
            pass

        return results


async def asyncio_open_connection(host: str, port: int, ssl: ssl.SSLContext, server_hostname: str):
    return await asyncio.open_connection(host, port, ssl=ssl, server_hostname=server_hostname)
