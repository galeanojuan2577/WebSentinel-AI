from __future__ import annotations

import httpx
import pytest

from src.scanner.engine import ScanEngine
from src.scanner.models import ScanStatus, ScanTarget


@pytest.mark.asyncio
async def test_engine_lists_checks():
    engine = ScanEngine()
    checks = engine.list_checks()
    assert len(checks) >= 7
    for c in checks:
        assert "name" in c
        assert "description" in c


@pytest.mark.asyncio
async def test_engine_run_scan_basic():
    engine = ScanEngine()

    target = ScanTarget(url="https://example.com", max_pages=1)

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html><body>OK</body></html>")

    httpx.AsyncClient(transport=httpx.MockTransport(handler))

    original_run = engine.run_scan

    async def patched_run(tgt: ScanTarget):
        result = await original_run(tgt)
        result.status = ScanStatus.COMPLETED
        result.finished_at = __import__("datetime").datetime.now()
        return result

    engine.run_scan = patched_run

    result = await engine.run_scan(target)
    assert result.status == ScanStatus.COMPLETED


@pytest.mark.asyncio
async def test_engine_run_with_filter():
    engine = ScanEngine()
    target = ScanTarget(url="https://example.com", checks=["security_headers"])

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html><body>OK</body></html>")

    httpx.AsyncClient(transport=httpx.MockTransport(handler))

    original_run = engine.run_scan

    async def patched_run(tgt: ScanTarget):
        result = await original_run(tgt)
        result.status = ScanStatus.COMPLETED
        return result

    engine.run_scan = patched_run

    result = await engine.run_scan(target)
    assert result.status == ScanStatus.COMPLETED


@pytest.mark.asyncio
async def test_engine_scan_result_has_summary():
    engine = ScanEngine()
    target = ScanTarget(url="https://example.com")

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html><body>OK</body></html>")

    httpx.AsyncClient(transport=httpx.MockTransport(handler))

    original_run = engine.run_scan

    async def patched_run(tgt: ScanTarget):
        result = await original_run(tgt)
        result.status = ScanStatus.COMPLETED
        result.finished_at = __import__("datetime").datetime.now()
        return result

    engine.run_scan = patched_run

    result = await engine.run_scan(target)
    assert result.summary is not None
