from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from src.api.main import app


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"


@pytest.mark.asyncio
async def test_list_checks(client):
    resp = await client.get("/checks")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["checks"]) >= 7


@pytest.mark.asyncio
async def test_start_scan(client):
    resp = await client.post("/scan", json={"url": "https://example.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "started"
    assert "scan_id" in data


@pytest.mark.asyncio
async def test_get_scan_not_found(client):
    resp = await client.get("/scan/nonexistent")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_list_scans(client):
    resp = await client.get("/scans")
    assert resp.status_code == 200
    data = resp.json()
    assert "active" in data
    assert "completed" in data
