from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from src.scanner.checks.ports import PortsCheck


@pytest.mark.asyncio
async def test_ports_check_no_extra_ports():
    check = PortsCheck()

    async def mock_open(host, port):
        if port in (80, 443):
            writer = AsyncMock()
            writer.close = lambda: None
            return AsyncMock(), writer
        raise OSError("Connection refused")

    with patch("asyncio.open_connection", side_effect=mock_open):
        from httpx import AsyncClient

        async with AsyncClient() as client:
            results = await check.run("https://example.com", client)

    extra = [r for r in results if "Open Port" in r.name]
    assert len(extra) == 0


@pytest.mark.asyncio
async def test_ports_check_name():
    check = PortsCheck()
    assert check.name == "open_ports"
    assert check.description
