from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from src.scanner.checks.base import BaseCheck
from src.scanner.models import CheckResult, Severity

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "'-alert(1)-'",
    '"><script>alert(1)</script>',
]

XSS_PATTERNS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)",
    "alert(1)",
]


class XSSCheck(BaseCheck):
    name = "reflected_xss"
    description = "Tests for reflected Cross-Site Scripting vulnerabilities in URL parameters and forms"

    async def run(self, url: str, client: httpx.AsyncClient) -> list[CheckResult]:
        results: list[CheckResult] = []

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            params = {"q": [""], "search": [""], "query": [""], "s": [""]}

        for param_name, original_values in params.items():
            for payload in XSS_PAYLOADS:
                test_params = {k: v[0] if k != param_name else payload for k, v in params.items()}
                new_query = urlencode(test_params)
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    resp = await client.get(test_url, follow_redirects=True, timeout=15)
                    body = resp.text

                    for pattern in XSS_PATTERNS:
                        if pattern in body:
                            results.append(
                                CheckResult(
                                    name="Reflected XSS",
                                    description=f"El parámetro '{param_name}' refleja el payload XSS en la respuesta sin sanitizar.",
                                    severity=Severity.HIGH,
                                    url=test_url,
                                    evidence=f"Payload: {payload}\nPattern found: {pattern}",
                                    remediation="1. Escapar toda entrada de usuario con encoding HTML context-aware.\n"
                                    "2. Usar Content-Security-Policy como defensa en profundidad.\n"
                                    "3. Validar y sanitizar inputs del lado del servidor.\n"
                                    "4. Usar bibliotecas como OWASP Java Encoder o Bleach (Python).",
                                    references=[
                                        "https://owasp.org/www-community/attacks/xss/",
                                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                                    ],
                                )
                            )
                            break
                except (httpx.TimeoutException, httpx.RequestError):
                    continue
                break

        return results
