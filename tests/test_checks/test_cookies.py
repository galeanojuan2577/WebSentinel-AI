from __future__ import annotations

import httpx
import pytest

from src.scanner.checks.cookies import CookiesCheck


@pytest.mark.asyncio
async def test_cookies_check_insecure():
    check = CookiesCheck()

    async def handler(request: httpx.Request) -> httpx.Response:
        resp = httpx.Response(200)
        resp.headers["Set-Cookie"] = "session=abc123; Path=/"
        return resp

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    results = await check.run("https://example.com", client)
    await client.aclose()

    insecure = [r for r in results if "Insecure" in r.name]
    missing_httponly = [r for r in results if "HttpOnly" in r.name]
    assert len(insecure) >= 1
    assert len(missing_httponly) >= 1


@pytest.mark.asyncio
async def test_cookies_check_secure():
    check = CookiesCheck()

    async def handler(request: httpx.Request) -> httpx.Response:
        resp = httpx.Response(200)
        resp.headers["Set-Cookie"] = "session=abc123; Secure; HttpOnly; SameSite=Lax; Path=/"
        return resp

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    results = await check.run("https://example.com", client)
    await client.aclose()

    insecure = [r for r in results if "Insecure" in r.name]
    assert len(insecure) == 0


@pytest.mark.asyncio
async def test_cookies_check_no_cookies():
    check = CookiesCheck()

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    results = await check.run("https://example.com", client)
    await client.aclose()

    assert len(results) == 0
