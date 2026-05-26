from __future__ import annotations

import httpx
import pytest

from src.scanner.checks.headers import SECURITY_HEADERS, HeadersCheck


@pytest.mark.asyncio
async def test_headers_check_missing_all():
    check = HeadersCheck()

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    results = await check.run("https://example.com", client)
    await client.aclose()

    found_names = {r.name for r in results}
    for header_key in SECURITY_HEADERS:
        assert f"Missing {SECURITY_HEADERS[header_key][0]}" in found_names


@pytest.mark.asyncio
async def test_headers_check_all_present():
    check = HeadersCheck()

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "Content-Security-Policy": "default-src 'self'",
                "Strict-Transport-Security": "max-age=31536000",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=()",
                "X-XSS-Protection": "1; mode=block",
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    results = await check.run("https://example.com", client)
    await client.aclose()

    missing = [r for r in results if "Missing" in r.name]
    assert len(missing) == 0


@pytest.mark.asyncio
async def test_headers_check_server_info_disclosure():
    check = HeadersCheck()

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "Server": "Apache/2.4.41",
                "X-Powered-By": "PHP/8.0",
            },
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    results = await check.run("https://example.com", client)
    await client.aclose()

    info_disclosure = [r for r in results if "Information Disclosure" in r.name]
    assert len(info_disclosure) >= 2


@pytest.mark.asyncio
async def test_headers_check_timeout():
    check = HeadersCheck()

    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("Timeout", request=request)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), timeout=1)
    results = await check.run("https://example.com", client)
    await client.aclose()

    assert any("Timeout" in r.name for r in results)
