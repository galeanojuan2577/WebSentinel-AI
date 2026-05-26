from __future__ import annotations

from urllib.parse import urlparse

import httpx

from src.scanner.checks.base import BaseCheck
from src.scanner.models import CheckResult, Severity

COMMON_PATHS = [
    "/admin",
    "/administrator",
    "/login",
    "/wp-admin",
    "/wp-login.php",
    "/backup",
    "/backups",
    "/.env",
    "/.git/config",
    "/config",
    "/config.php",
    "/db",
    "/database",
    "/phpinfo.php",
    "/info.php",
    "/test",
    "/api",
    "/api/v1",
    "/swagger",
    "/docs",
    "/.well-known/security.txt",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/shell",
    "/cmd",
    "/upload",
    "/uploads",
    "/files",
    "/download",
    "/private",
    "/restore",
    "/.htaccess",
    "/server-status",
    "/server-info",
    "/graphql",
    "/.aws/credentials",
    "/.ssh",
    "/vendor",
    "/composer.json",
    "/package.json",
    "/Dockerfile",
]

SENSITIVE_PATTERNS = {
    "password": "Potential credential exposure",
    "passwd": "Potential password file",
    "secret": "Potential secret key exposure",
    "api_key": "API key exposure",
    "token": "Token exposure",
    "DB_HOST": "Database configuration exposure",
    "DB_PASSWORD": "Database password exposure",
}

_SPA_MARKERS = [
    '<div id="root">',
    '<div id="app">',
    "reactroot",
    "ng-version",
    "__nuxt",
    "createRoot(",
]

_NON_HTML_PATHS = {
    "/.env",
    "/.git/config",
    "/.aws/credentials",
    "/.ssh",
    "/backup",
    "/backups",
    "/config",
    "/composer.json",
    "/package.json",
    "/Dockerfile",
    "/.htaccess",
}


def _is_html_response(resp: httpx.Response) -> bool:
    ct = resp.headers.get("content-type", "").lower()
    return "text/html" in ct or "application/xhtml" in ct


def _body_looks_like_html(body: str) -> bool:
    """Check if the response body looks like an HTML document."""
    body_stripped = body.strip()
    if not body_stripped:
        return False
    return body_stripped.startswith("<!") or body_stripped.startswith("<html") or body_stripped.startswith("<")


def _has_spa_markers(body: str) -> bool:
    return any(marker in body for marker in _SPA_MARKERS)


class DirectoriesCheck(BaseCheck):
    name = "directory_enumeration"
    description = "Enumerates common sensitive paths and files for information disclosure"

    async def run(self, url: str, client: httpx.AsyncClient) -> list[CheckResult]:
        results: list[CheckResult] = []

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        root_body = ""
        root_is_spa = False
        try:
            root_resp = await client.get(base, follow_redirects=True, timeout=10)
            if root_resp.status_code == 200:
                root_body = root_resp.text or ""
                root_is_spa = _has_spa_markers(root_body)
        except (httpx.TimeoutException, httpx.RequestError):
            pass

        for path in COMMON_PATHS:
            test_url = f"{base}{path}"
            try:
                resp = await client.get(test_url, follow_redirects=False, timeout=10)

                if resp.status_code == 200:
                    body = resp.text or ""

                    is_html = _is_html_response(resp) or _body_looks_like_html(body)

                    if root_is_spa and is_html:
                        if body.strip() == root_body.strip():
                            continue

                        if path in _NON_HTML_PATHS and _token_overlap(body, root_body) > 0.7:
                            results.append(
                                CheckResult(
                                    name="SPA Catch-All Route",
                                    description=f"La ruta '{path}' devuelve 200 con la página del SPA, no un archivo real (catch-all routing).",
                                    severity=Severity.INFO,
                                    url=test_url,
                                    remediation="Configurar el servidor para que devuelva 404 en rutas que no correspondan a archivos reales.",
                                )
                            )
                            continue

                    if not body.strip():
                        results.append(
                            CheckResult(
                                name="Empty Response",
                                description=f"La ruta '{path}' devuelve HTTP 200 pero el body está vacío.",
                                severity=Severity.INFO,
                                url=test_url,
                                remediation="Verificar que no haya contenido sensible en esta ruta.",
                            )
                        )
                        continue

                    severity = Severity.MEDIUM
                    if any(
                        sens in path
                        for sens in (
                            ".env",
                            ".git",
                            ".aws",
                            ".ssh",
                            "backup",
                            "backups",
                        )
                    ):
                        severity = Severity.HIGH

                    evidence = None
                    body_lower = body.lower()
                    matched_patterns = [k for k in SENSITIVE_PATTERNS if k in body_lower]
                    if matched_patterns:
                        evidence = f"Sensitive patterns detected: {', '.join(matched_patterns)}"
                        severity = Severity.HIGH

                    results.append(
                        CheckResult(
                            name="Exposed Path",
                            description=f"La ruta '{path}' es accesible públicamente (HTTP {resp.status_code}).",
                            severity=severity,
                            url=test_url,
                            evidence=evidence,
                            remediation="1. Eliminar archivos sensibles del servidor web.\n"
                            "2. Configurar reglas de denegación en el servidor web.\n"
                            "3. No incluir archivos de configuración, backups o .git en el directorio público.",
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/"
                            ],
                        )
                    )
                elif resp.status_code in (401, 403):
                    results.append(
                        CheckResult(
                            name="Protected Path (requires auth)",
                            description=f"La ruta '{path}' está protegida (HTTP {resp.status_code}). Puede ser un panel administrativo.",
                            severity=Severity.LOW,
                            url=test_url,
                            remediation="Verificar que el acceso esté correctamente restringido y que no haya vulnerabilidades de autenticación.",
                        )
                    )
            except (httpx.TimeoutException, httpx.RequestError):
                continue

        return results


def _token_overlap(a: str, b: str) -> float:
    tokens_a = set(_tokenize(a.lower()))
    tokens_b = set(_tokenize(b.lower()))
    if not tokens_a or not tokens_b:
        return 0.0
    intersection = tokens_a & tokens_b
    return len(intersection) / max(len(tokens_a), len(tokens_b))


def _tokenize(text: str) -> list[str]:
    for sep in ("<", ">", " ", '"', "'", "=", "/", "."):
        text = text.replace(sep, " ")
    return [t for t in text.split() if len(t) > 1]
