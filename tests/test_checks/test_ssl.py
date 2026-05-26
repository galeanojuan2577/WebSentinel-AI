from __future__ import annotations

import httpx
import pytest

from src.scanner.checks.ssl import SSLCheck
from src.scanner.models import CheckResult


@pytest.mark.asyncio
async def test_ssl_check_no_https(sample_url):
    check = SSLCheck()

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    results = await check.run(sample_url, client)
    await client.aclose()

    assert isinstance(results, list)
    assert len(results) > 0
