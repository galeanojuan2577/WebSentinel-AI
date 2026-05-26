from __future__ import annotations

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from src.scanner.checks.base import BaseCheck
from src.scanner.models import CheckResult, Severity

SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "' UNION SELECT NULL--",
    "' AND 1=1--",
    "' AND 1=2--",
]

ERROR_PATTERNS = [
    "sql syntax",
    "mysql_fetch",
    "ora-",
    "sqlite",
    "postgresql",
    "driver error",
    "warning: mysql",
    "unclosed quotation mark",
    "you have an error in your sql",
    "microsoft ole db",
    "unknown column",
    "division by zero",
]


class SQLICheck(BaseCheck):
    name = "sql_injection"
    description = "Tests for SQL Injection vulnerabilities in URL parameters"

    async def run(self, url: str, client: httpx.AsyncClient) -> list[CheckResult]:
        results: list[CheckResult] = []

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            params = {"id": [""], "page": [""], "cat": [""], "product": [""]}

        for param_name in params:
            for payload in SQLI_PAYLOADS:
                test_params = {}
                for k, v in params.items():
                    test_params[k] = payload if k == param_name else v[0]
                new_query = urlencode(test_params)
                test_url = urlunparse(parsed._replace(query=new_query))

                try:
                    base_resp = await client.get(url, follow_redirects=True, timeout=15)
                    test_resp = await client.get(test_url, follow_redirects=True, timeout=15)
                    body_lower = test_resp.text.lower()

                    for pattern in ERROR_PATTERNS:
                        if pattern in body_lower:
                            results.append(CheckResult(
                                name="Potential SQL Injection",
                                description=f"El parámetro '{param_name}' parece vulnerable a SQL Injection. "
                                            f"El servidor expone errores de base de datos.",
                                severity=Severity.HIGH,
                                url=test_url,
                                evidence=f"Payload: {payload}\nError pattern matched: {pattern}",
                                remediation="1. Usar consultas parametrizadas (prepared statements).\n"
                                            "2. Validar y sanitizar todos los inputs.\n"
                                            "3. Usar un ORM que escape automáticamente (SQLAlchemy, Django ORM).\n"
                                            "4. Configurar el manejador de errores de la BD para no exponer detalles.",
                                references=[
                                    "https://owasp.org/www-community/attacks/SQL_Injection",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                                ],
                            ))
                            break

                    if test_resp.status_code != base_resp.status_code and test_resp.status_code in (500, 404, 403):
                        results.append(CheckResult(
                            name="Potential SQL Injection (Behavior Change)",
                            description=f"El parámetro '{param_name}' causa un cambio de comportamiento "
                                        f"(status {base_resp.status_code} → {test_resp.status_code}) "
                                        f"que sugiere una posible inyección SQL.",
                            severity=Severity.MEDIUM,
                            url=test_url,
                            evidence=f"Payload: {payload}\nStatus change: {base_resp.status_code} → {test_resp.status_code}",
                            remediation="Revisar el parámetro manualmente con herramientas especializadas como sqlmap.",
                            references=["https://sqlmap.org/"],
                        ))
                except (httpx.TimeoutException, httpx.RequestError):
                    continue
                break

        return results
