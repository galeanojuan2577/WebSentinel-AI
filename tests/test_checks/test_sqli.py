from __future__ import annotations

from urllib.parse import unquote

import httpx
import pytest

from src.scanner.checks.sqli import SQLICheck


@pytest.mark.asyncio
async def test_sqli_check_error_pattern():
    check = SQLICheck()

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>SQL syntax error near '1' at line 1</html>")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    results = await check.run("https://example.com?id=1", client)
    await client.aclose()

    sqli_findings = [r for r in results if "SQL Injection" in r.name]
    assert len(sqli_findings) >= 1


@pytest.mark.asyncio
async def test_sqli_check_clean():
    check = SQLICheck()

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>OK</html>")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    results = await check.run("https://example.com?id=1", client)
    await client.aclose()

    sqli_findings = [r for r in results if "SQL Injection" in r.name]
    assert len(sqli_findings) == 0


@pytest.mark.asyncio
async def test_sqli_check_behavior_change():
    check = SQLICheck()

    async def handler(request: httpx.Request) -> httpx.Response:
        decoded = unquote(str(request.url))
        if "'" in decoded:
            return httpx.Response(500, text="<html>Error</html>")
        return httpx.Response(200, text="<html>OK</html>")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    results = await check.run("https://example.com?id=1", client)
    await client.aclose()

    behavior = [r for r in results if "Behavior Change" in r.name]
    assert len(behavior) >= 1
