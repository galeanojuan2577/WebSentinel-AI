from __future__ import annotations

import httpx
import pytest

from src.scanner.checks.directories import DirectoriesCheck


@pytest.mark.asyncio
async def test_directories_check_finds_real_exposed_content():
    """Real sensitive content should still be detected."""
    check = DirectoriesCheck()

    async def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/" or path == "":
            return httpx.Response(200, text="<html><body>Homepage</body></html>")
        if path in ("/.env",):
            return httpx.Response(200, text="DB_PASSWORD=secret", headers={"content-type": "text/plain"})
        if path in ("/backup",):
            return httpx.Response(200, text="backup_data_2024.sql", headers={"content-type": "application/octet-stream"})
        if path in ("/.git/config",):
            return httpx.Response(200, text="[core]\n\trepositoryformatversion = 0", headers={"content-type": "text/plain"})
        return httpx.Response(404, text="Not Found")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    results = await check.run("https://example.com", client)
    await client.aclose()

    exposed = [r for r in results if r.name == "Exposed Path"]
    assert len(exposed) >= 3


@pytest.mark.asyncio
async def test_directories_check_filters_spa_fallback():
    """SPAs that serve identical HTML for all paths should not trigger false positives."""
    check = DirectoriesCheck()
    spa_html = (
        "<!DOCTYPE html><html><head><title>My App</title></head>"
        "<body><div id=\"root\"></div><script src=\"/assets/index.js\"></script>"
        "</body></html>"
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=spa_html, headers={"content-type": "text/html"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    results = await check.run("https://example.com", client)
    await client.aclose()

    exposed = [r for r in results if r.name == "Exposed Path"]
    assert len(exposed) == 0


@pytest.mark.asyncio
async def test_directories_check_non_html_paths_in_spa():
    """Non-HTML paths (like /.env, /backup) in SPAs should be flagged as catch-all."""
    check = DirectoriesCheck()
    base = (
        "<html><head><title>App</title></head>"
        "<body><div id=\"root\"></div></body></html>"
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        route_data = f'<script>window.__data="{path}"</script>'
        return httpx.Response(200, text=route_data + base, headers={"content-type": "text/html"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    results = await check.run("https://example.com", client)
    await client.aclose()

    spa_routes = [r for r in results if r.name == "SPA Catch-All Route"]
    assert len(spa_routes) > 0

    non_html_paths = {"/.env", "/.git/config", "/.aws/credentials", "/.ssh", "/backup", "/backups"}
    for r in results:
        for np in non_html_paths:
            if np in r.url and r.name == "Exposed Path":
                pytest.fail(f"Non-HTML path {np} should not be 'Exposed Path': {r}")


@pytest.mark.asyncio
async def test_directories_check_real_html_pages_in_spa_not_filtered():
    """Normal-looking HTML paths (like /admin, /login) in SPAs should still be
    reported when they're real pages, not just the SPA shell."""
    check = DirectoriesCheck()
    spa_shell = "<html><head><title>App</title></head><body><div id=\"root\"></div></body></html>"

    async def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/" or path == "":
            return httpx.Response(200, text=spa_shell, headers={"content-type": "text/html"})
        if path in ("/admin", "/login"):
            return httpx.Response(200, text="<html><body><h1>Admin Panel</h1><form>login</form></body></html>",
                                  headers={"content-type": "text/html"})
        return httpx.Response(200, text=spa_shell + f"<script>route/{path}</script>",
                              headers={"content-type": "text/html"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    results = await check.run("https://example.com", client)
    await client.aclose()

    real_pages = [r for r in results if r.name == "Exposed Path" and any(p in r.url for p in ("/admin", "/login"))]
    assert len(real_pages) >= 2


@pytest.mark.asyncio
async def test_directories_check_all_protected():
    check = DirectoriesCheck()

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, text="Not Found")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    results = await check.run("https://example.com", client)
    await client.aclose()

    exposed = [r for r in results if r.name == "Exposed Path"]
    assert len(exposed) == 0


@pytest.mark.asyncio
async def test_directories_check_protected_paths():
    check = DirectoriesCheck()

    async def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/" or path == "":
            return httpx.Response(200, text="<html><body>Homepage</body></html>")
        if path in ("/admin", "/login"):
            return httpx.Response(403, text="Forbidden")
        return httpx.Response(404, text="Not Found")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    results = await check.run("https://example.com", client)
    await client.aclose()

    protected = [r for r in results if r.name == "Protected Path (requires auth)"]
    assert len(protected) >= 2
