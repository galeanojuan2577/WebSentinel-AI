from __future__ import annotations

from urllib.parse import unquote

import httpx
import pytest

from src.scanner.checks.xss import XSSCheck


@pytest.mark.asyncio
async def test_xss_check_reflected():
    check = XSSCheck()

    async def handler(request: httpx.Request) -> httpx.Response:
        decoded = unquote(str(request.url))
        if "alert('xss')" in decoded or "<script>" in decoded:
            return httpx.Response(200, text="<html><body><script>alert('xss')</script></body></html>")
        return httpx.Response(200, text="<html><body>OK</body></html>")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    results = await check.run("https://example.com?q=test", client)
    await client.aclose()

    xss_findings = [r for r in results if r.name == "Reflected XSS"]
    assert len(xss_findings) >= 1


@pytest.mark.asyncio
async def test_xss_check_no_reflection():
    check = XSSCheck()

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html><body>OK</body></html>")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    results = await check.run("https://example.com?q=test", client)
    await client.aclose()

    xss_findings = [r for r in results if r.name == "Reflected XSS"]
    assert len(xss_findings) == 0


@pytest.mark.asyncio
async def test_xss_check_no_params():
    check = XSSCheck()

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html><body>OK</body></html>")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    results = await check.run("https://example.com", client)
    await client.aclose()

    assert isinstance(results, list)
