from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from src.api.auth import ensure_default_user
from src.api.database import init_db
from src.api.main import app


@pytest.fixture(autouse=True)
async def setup_db():
    await init_db()
    await ensure_default_user()


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"


@pytest.mark.asyncio
async def test_list_checks(client):
    resp = await client.get("/api/checks")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["checks"]) >= 7


@pytest.mark.asyncio
async def test_start_scan(client):
    resp = await client.post("/api/scan", json={"url": "https://example.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "started"
    assert "scan_id" in data


@pytest.mark.asyncio
async def test_get_scan_not_found(client):
    resp = await client.get("/api/scan/nonexistent")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_list_scans(client):
    resp = await client.get("/api/scans")
    assert resp.status_code == 200
    data = resp.json()
    assert "active" in data
    assert "completed" in data
