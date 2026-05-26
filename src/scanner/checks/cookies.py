from __future__ import annotations

import httpx

from src.scanner.checks.base import BaseCheck
from src.scanner.models import CheckResult, Severity


class CookiesCheck(BaseCheck):
    name = "cookie_security"
    description = "Audits cookie security attributes (Secure, HttpOnly, SameSite)"

    async def run(self, url: str, client: httpx.AsyncClient) -> list[CheckResult]:
        results: list[CheckResult] = []

        try:
            resp = await client.get(url, follow_redirects=True)
            cookies = resp.cookies

            for cookie in cookies.jar:
                name = cookie.name

                if not cookie.secure:
                    results.append(
                        CheckResult(
                            name=f"Insecure Cookie: {name}",
                            description=f"La cookie '{name}' no tiene la flag Secure. Se envía incluso por conexiones HTTP.",
                            severity=Severity.MEDIUM,
                            url=url,
                            evidence=f"Cookie: {name}={cookie.value}",
                            remediation="Agregar la flag 'Secure' a la cookie para que solo se transmita por HTTPS.",
                            references=["https://owasp.org/www-community/controls/SecureFlag"],
                        )
                    )

                if not cookie.has_nonstandard_attr("httponly"):
                    results.append(
                        CheckResult(
                            name=f"Missing HttpOnly Flag: {name}",
                            description=f"La cookie '{name}' no tiene la flag HttpOnly. Puede ser accedida por JavaScript, aumentando el riesgo de XSS.",
                            severity=Severity.MEDIUM,
                            url=url,
                            evidence=f"Cookie: {name}={cookie.value}",
                            remediation="Agregar la flag 'HttpOnly' a la cookie para que no sea accesible desde JavaScript.",
                            references=["https://owasp.org/www-community/HttpOnly"],
                        )
                    )

                samesite = getattr(cookie, "samesite", None)
                if not samesite or samesite.lower() == "none":
                    results.append(
                        CheckResult(
                            name=f"Missing SameSite Flag: {name}",
                            description=f"La cookie '{name}' no tiene SameSite o está en 'None'. Vulnerable a ataques CSRF.",
                            severity=Severity.LOW,
                            url=url,
                            evidence=f"Cookie: {name}={cookie.value}, SameSite: {samesite}",
                            remediation="Agregar 'SameSite=Lax' o 'SameSite=Strict' a la cookie para prevenir CSRF.",
                            references=["https://owasp.org/www-community/controls/SameSite"],
                        )
                    )

        except (httpx.TimeoutException, httpx.RequestError):
            results.append(
                CheckResult(
                    name="Cookie Check Failed",
                    description="No se pudieron analizar las cookies debido a un error de conexión.",
                    severity=Severity.INFO,
                    url=url,
                    remediation="Verificar que el servidor responda correctamente.",
                )
            )

        return results
