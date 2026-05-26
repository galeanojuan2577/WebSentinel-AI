from __future__ import annotations

import httpx

from src.scanner.checks.base import BaseCheck
from src.scanner.models import CheckResult, Severity

SECURITY_HEADERS = {
    "content-security-policy": (
        "Content-Security-Policy",
        "Protege contra XSS y data injection al controlar qué recursos puede cargar el navegador.",
        "Agregar la cabecera CSP con una política adecuada, por ejemplo:\n"
        "Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted-cdn.com",
        "https://owasp.org/www-project-secure-headers/#content-security-policy",
    ),
    "strict-transport-security": (
        "Strict-Transport-Security",
        "Obliga a los navegadores a conectarse siempre por HTTPS, previniendo ataques MITM.",
        "Agregar al servidor web:\n"
        "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "https://owasp.org/www-project-secure-headers/#http-strict-transport-security",
    ),
    "x-frame-options": (
        "X-Frame-Options",
        "Previene clickjacking al controlar si la página puede ser incrustada en un <frame>.",
        "Agregar:\n"
        "X-Frame-Options: DENY\n"
        "o SAMEORIGIN si necesitas iframes del mismo dominio.",
        "https://owasp.org/www-project-secure-headers/#x-frame-options",
    ),
    "x-content-type-options": (
        "X-Content-Type-Options",
        "Evita que el navegador interprete archivos como un tipo MIME diferente al declarado.",
        "Agregar:\n"
        "X-Content-Type-Options: nosniff",
        "https://owasp.org/www-project-secure-headers/#x-content-type-options",
    ),
    "referrer-policy": (
        "Referrer-Policy",
        "Controla cuánta información de la URL de origen se envía en el header Referer.",
        "Agregar:\n"
        "Referrer-Policy: strict-origin-when-cross-origin",
        "https://owasp.org/www-project-secure-headers/#referrer-policy",
    ),
    "permissions-policy": (
        "Permissions-Policy",
        "Restringe qué APIs del navegador puede usar la página (cámara, micrófono, etc.).",
        "Agregar:\n"
        "Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "https://owasp.org/www-project-secure-headers/#permissions-policy",
    ),
    "x-xss-protection": (
        "X-XSS-Protection",
        "Cabecera legacy para activar el filtro XSS del navegador (obsoleta, pero aún recomendada en algunos contextos).",
        "Agregar:\n"
        "X-XSS-Protection: 1; mode=block\n"
        "Nota: esta cabecera está obsoleta en navegadores modernos; CSP es la solución actual.",
        "https://owasp.org/www-project-secure-headers/#x-xss-protection",
    ),
}

_SERVER_INFO_HEADERS = ("server", "x-powered-by", "x-aspnet-version")


class HeadersCheck(BaseCheck):
    name = "security_headers"
    description = "Analyzes HTTP security headers and information disclosure"

    async def run(self, url: str, client: httpx.AsyncClient) -> list[CheckResult]:
        results: list[CheckResult] = []
        try:
            resp = await client.get(url, follow_redirects=True)
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            for header_key, (display_name, desc, remediation, ref) in SECURITY_HEADERS.items():
                if header_key not in headers_lower:
                    results.append(CheckResult(
                        name=f"Missing {display_name}",
                        description=desc,
                        severity=Severity.MEDIUM,
                        url=url,
                        remediation=remediation,
                        references=[ref],
                    ))

            for h in _SERVER_INFO_HEADERS:
                value = headers_lower.get(h)
                if value:
                    results.append(CheckResult(
                        name=f"Information Disclosure: {h}",
                        description=f"El header {h} expone información del servidor: '{value}'.",
                        severity=Severity.LOW,
                        url=url,
                        evidence=value,
                        remediation="Eliminar u ofuscar el header {0} en la configuración del servidor web.".format(h),
                        references=["https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/"],
                    ))

        except httpx.TimeoutException:
            results.append(CheckResult(
                name="Timeout",
                description="La solicitud a la URL excedió el tiempo de espera.",
                severity=Severity.INFO,
                url=url,
                remediation="Verificar que el servidor responda correctamente.",
            ))
        except Exception as exc:
            results.append(CheckResult(
                name="Connection Error",
                description=f"No se pudo conectar a la URL: {exc}",
                severity=Severity.INFO,
                url=url,
                remediation="Verificar que la URL sea accesible.",
            ))
        return results
