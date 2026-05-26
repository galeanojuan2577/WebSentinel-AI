from __future__ import annotations

import asyncio
import json
import logging
import uuid
import zipfile
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from fastapi import (
    APIRouter,
    Depends,
    FastAPI,
    File,
    HTTPException,
    Query,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.ai.chat import AIChatService, ChatRequest
from src.ai.enricher import AIEnricher
from src.api.auth import (
    LoginRequest,
    TokenResponse,
    create_access_token,
    ensure_default_user,
    get_current_user,
    verify_password,
)
from src.api.database import async_session_factory, get_db, init_db
from src.api.db_models import Finding as DBFinding
from src.api.db_models import Scan as DBScan
from src.api.db_models import User as DBUser
from src.orchestrator.pipeline import (
    PipelineRequest,
    PipelineState,
    PipelineStatus,
    StepResult,
    _build_default_pipeline,
    get_pipeline,
    list_pipelines,
    run_pipeline,
)
from src.scanner.engine import ScanEngine
from src.scanner.models import ScanTarget, Severity
from src.scanner.noir import NoirScanner

logger = logging.getLogger("websentinel.api")

engine = ScanEngine()
active_scans: dict[str, asyncio.Task] = {}
scan_results: dict[str, dict] = {}
websocket_clients: list[WebSocket] = []
noir: NoirScanner = NoirScanner()
ai_enricher: AIEnricher = AIEnricher()
ai_chat: AIChatService = AIChatService(ai_enricher)


async def _broadcast(message: dict):
    for ws in websocket_clients[:]:
        try:
            await ws.send_json(message)
        except Exception:
            websocket_clients.remove(ws)


def _noir_progress_cb(scan_id: str, loop: asyncio.AbstractEventLoop):
    def cb(percent: int, msg: str):
        asyncio.run_coroutine_threadsafe(
            _broadcast(
                {
                    "type": "noir_progress",
                    "scan_id": scan_id,
                    "percent": percent,
                    "message": msg,
                }
            ),
            loop,
        )

    return cb


async def _save_scan_to_db(
    scan_id: str,
    scan_type: str,
    target: str,
    status: str,
    findings: list | None = None,
    error: str | None = None,
):
    try:
        async with async_session_factory() as session:
            db_scan = DBScan(
                id=scan_id,
                scan_type=scan_type,
                target=target,
                status=status,
                finished_at=datetime.now(),
                error=error,
                total_findings=len(findings) if findings else 0,
            )
            if findings:
                sev_counts: dict[str, int] = {s.value: 0 for s in Severity}
                for f in findings:
                    sev = f.get("severity", "info")
                    sev_counts[sev] = sev_counts.get(sev, 0) + 1
                db_scan.severity_summary = sev_counts  # type: ignore[assignment]
                for f in findings:
                    db_scan.findings.append(
                        DBFinding(
                            name=f.get("name", "Unknown"),
                            description=f.get("description", ""),
                            severity=f.get("severity", "info"),
                            url=f.get("url", target),
                            evidence=f.get("evidence"),
                            remediation=f.get("remediation", ""),
                            references=f.get("references", []),
                            source=f.get("source", scan_type),
                        )
                    )
            session.add(db_scan)
            await session.commit()
    except Exception as e:
        logger.error("Failed to save scan %s to DB: %s", scan_id, e)


async def _save_pipeline_to_db(pipeline_id: str, state):
    try:
        for s in state.steps:
            if s.status != "completed" or not s.result:
                continue
            findings = s.result.get(
                "findings",
                s.result.get("vulnerabilities", s.result.get("enriched_findings", [])),
            )
            if not findings:
                continue
            scan_type = s.step_type.value if hasattr(s.step_type, "value") else str(s.step_type)
            await _save_scan_to_db(
                scan_id=f"{pipeline_id}_{s.step_id.split('_')[-1]}" if "_" in s.step_id else pipeline_id,
                scan_type=f"pipeline_{scan_type}",
                target=state.target,
                status="completed",
                findings=findings,
            )
    except Exception as e:
        logger.error("Failed to save pipeline %s to DB: %s", pipeline_id, e)


async def _run_scan_task(scan_id: str, target: ScanTarget):
    try:
        await _broadcast({"type": "scan_started", "scan_id": scan_id, "target": target.url})
        result = await engine.run_scan(target)
        scan_data = result.model_dump(mode="json")
        scan_data["duration_seconds"] = result.duration_seconds
        scan_data["summary"] = result.summary
        scan_results[scan_id] = scan_data
        await _broadcast({"type": "scan_completed", "scan_id": scan_id, "result": scan_data})
        vs = [v.model_dump(mode="json") for v in result.vulnerabilities]
        asyncio.create_task(_save_scan_to_db(scan_id, "web", target.url, "completed", findings=vs))
    except Exception as exc:
        logger.error("Scan %s failed: %s", scan_id, exc)
        scan_results[scan_id] = {
            "status": "failed",
            "error": str(exc),
            "target": {"url": target.url},
        }
        await _broadcast({"type": "scan_failed", "scan_id": scan_id, "error": str(exc)})
        asyncio.create_task(_save_scan_to_db(scan_id, "web", target.url, "failed", error=str(exc)))
    finally:
        active_scans.pop(scan_id, None)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("VulnScout API starting...")
    await init_db()
    await ensure_default_user()
    yield
    for scan_id, task in active_scans.items():
        task.cancel()
    active_scans.clear()


app = FastAPI(
    title="WebSentinel-AI API",
    version="0.3.0",
    description="AI-Powered Web Vulnerability Scanner & Remediation Platform",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

api = APIRouter(prefix="/api")


# ── Models ─────────────────────────────────────────────────────────────────


class ScanRequest(BaseModel):
    url: str
    checks: list[str] = ["all"]
    max_pages: int = 10
    follow_redirects: bool = True


class NetworkScanRequest(BaseModel):
    target: str = "local"
    scan_type: str = "quick"


class NoirAuditRequest(BaseModel):
    project_path: str = ""
    output_format: str = "json"


class ComprehensiveScanRequest(BaseModel):
    url: str
    include_cve: bool = True
    include_dns: bool = True
    include_subdomains: bool = True
    include_tech: bool = True


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    target: str


# ── Health ──────────────────────────────────────────────────────────────────


@api.get("/health")
async def health():
    return {"status": "ok", "version": "0.3.0"}


# ── Auth ────────────────────────────────────────────────────────────────────


@api.post("/auth/login", response_model=TokenResponse)
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(DBUser).where(DBUser.username == req.username))
    user = result.scalar_one_or_none()
    if not user or not verify_password(req.password, str(user.hashed_password)):  # type: ignore[arg-type]
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": user.username})
    return TokenResponse(access_token=token)


@api.get("/auth/me")
async def auth_me(user: Optional[DBUser] = Depends(get_current_user)):
    if user is None:
        return {"authenticated": False}
    return {
        "authenticated": True,
        "username": user.username,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }


# ── Checks ─────────────────────────────────────────────────────────────────


@api.get("/checks")
async def list_checks():
    return {"checks": engine.list_checks()}


# ── Web Scanner ────────────────────────────────────────────────────────────


@api.post("/scan", response_model=ScanResponse)
async def start_scan(req: ScanRequest):
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=422, detail="URL is required and cannot be empty")
    scan_id = uuid.uuid4().hex[:12]
    target = ScanTarget(
        url=req.url,
        checks=req.checks,
        max_pages=req.max_pages,
        follow_redirects=req.follow_redirects,
    )
    task = asyncio.create_task(_run_scan_task(scan_id, target))
    active_scans[scan_id] = task
    return ScanResponse(scan_id=scan_id, status="started", target=req.url)


@api.get("/scan/{scan_id}")
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    if scan_id in active_scans:
        return {"scan_id": scan_id, "status": "running"}
    result = scan_results.get(scan_id)
    if result:
        return result
    async with db as session:
        from sqlalchemy import select

        db_scan = (await session.execute(select(DBScan).where(DBScan.id == scan_id))).scalar_one_or_none()
        if not db_scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        return {
            "scan_id": db_scan.id,
            "target": db_scan.target,
            "status": db_scan.status,
            "scan_type": db_scan.scan_type,
            "started_at": db_scan.started_at.isoformat() if db_scan.started_at else None,
            "finished_at": db_scan.finished_at.isoformat() if db_scan.finished_at else None,
            "total_findings": db_scan.total_findings,
            "severity_summary": db_scan.severity_summary,
            "error": db_scan.error,
            "findings": [
                {
                    "id": f.id,
                    "name": f.name,
                    "description": f.description,
                    "severity": f.severity,
                    "url": f.url,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "references": f.references,
                    "source": f.source,
                    "status": f.status or "open",
                }
                for f in db_scan.findings
            ],
        }


@api.get("/scans")
async def list_scans():
    return {
        "active": list(active_scans.keys()),
        "completed": [
            {
                "scan_id": sid,
                "target": r.get("target", {}).get("url", "unknown"),
                "status": r.get("status"),
            }
            for sid, r in scan_results.items()
        ],
    }


# ── Link Scanner Comprehensive ─────────────────────────────────────────────


@api.post("/link/scan-comprehensive")
async def comprehensive_scan(req: ComprehensiveScanRequest):
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=422, detail="URL is required and cannot be empty")
    scan_id = uuid.uuid4().hex[:12]

    async def _progress(source: str, status: str):
        await _broadcast(
            {
                "type": "comprehensive_progress",
                "scan_id": scan_id,
                "source": source,
                "status": status,
            }
        )

    async def run_comprehensive():
        try:
            from src.scanner.comprehensive import run_comprehensive_scan

            result = await run_comprehensive_scan(
                url=req.url,
                include_tech=req.include_tech,
                include_subdomains=req.include_subdomains,
                include_cve=req.include_cve,
                include_dns=req.include_dns,
                progress_callback=_progress,
            )
            result["scan_id"] = scan_id
            result["status"] = "completed"
            scan_results[scan_id] = result
            await _broadcast(
                {
                    "type": "comprehensive_completed",
                    "scan_id": scan_id,
                    "result": result,
                }
            )
        except Exception as exc:
            logger.error(f"Comprehensive scan {scan_id} failed: {exc}")
            scan_results[scan_id] = {
                "status": "failed",
                "error": str(exc),
                "target": req.url,
            }
            await _broadcast({"type": "comprehensive_failed", "scan_id": scan_id, "error": str(exc)})
        finally:
            active_scans.pop(scan_id, None)

    task = asyncio.create_task(run_comprehensive())
    active_scans[scan_id] = task
    return {
        "scan_id": scan_id,
        "status": "started",
        "target": req.url,
        "sources": [
            "technology_detect",
            "subdomain_discovery",
            "cve_lookup",
            "dns_enumeration",
        ],
    }


def httpx_async_client():
    import httpx

    return httpx.AsyncClient(timeout=httpx.Timeout(30.0), follow_redirects=True, verify=False)


# ── Network Scanner ────────────────────────────────────────────────────────


@api.post("/network/scan")
async def network_scan(req: NetworkScanRequest):
    scan_id = uuid.uuid4().hex[:12]

    async def run_network_scan():
        try:
            await _broadcast(
                {
                    "type": "network_scan_started",
                    "scan_id": scan_id,
                    "target": req.target,
                }
            )
            from src.scanner.checks.network import NetworkScanCheck

            scanner = NetworkScanCheck()
            results = await scanner.run(req.target, None)
            scan_results[scan_id] = {
                "scan_id": scan_id,
                "status": "completed",
                "target": req.target,
                "findings": [r.model_dump(mode="json") for r in results],
            }
            await _broadcast(
                {
                    "type": "network_scan_completed",
                    "scan_id": scan_id,
                    "result": scan_results[scan_id],
                }
            )
        except Exception as exc:
            logger.error(f"Network scan {scan_id} failed: {exc}")
            scan_results[scan_id] = {
                "status": "failed",
                "error": str(exc),
                "target": req.target,
            }
            await _broadcast({"type": "network_scan_failed", "scan_id": scan_id, "error": str(exc)})
        finally:
            active_scans.pop(scan_id, None)

    task = asyncio.create_task(run_network_scan())
    active_scans[scan_id] = task
    return {"scan_id": scan_id, "status": "started", "target": req.target}


@api.get("/network/scan/{scan_id}")
async def get_network_scan(scan_id: str):
    if scan_id in active_scans:
        return {"scan_id": scan_id, "status": "running"}
    result = scan_results.get(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


@api.post("/network/wifi-scan")
async def wifi_scan():
    scan_id = uuid.uuid4().hex[:12]

    async def run_wifi_scan():
        try:
            await _broadcast({"type": "wifi_scan_started", "scan_id": scan_id})
            from src.scanner.checks.wifi import WiFiScanCheck

            scanner = WiFiScanCheck()
            results = await scanner.run("wifi://local", None)
            scan_results[scan_id] = {
                "scan_id": scan_id,
                "status": "completed",
                "target": "wifi://local",
                "findings": [r.model_dump(mode="json") for r in results],
            }
            await _broadcast(
                {
                    "type": "wifi_scan_completed",
                    "scan_id": scan_id,
                    "result": scan_results[scan_id],
                }
            )
        except Exception as exc:
            logger.error(f"WiFi scan {scan_id} failed: {exc}")
            scan_results[scan_id] = {
                "status": "failed",
                "error": str(exc),
                "target": "wifi://local",
            }
            await _broadcast({"type": "wifi_scan_failed", "scan_id": scan_id, "error": str(exc)})
        finally:
            active_scans.pop(scan_id, None)

    task = asyncio.create_task(run_wifi_scan())
    active_scans[scan_id] = task
    return {"scan_id": scan_id, "status": "started", "target": "wifi://local"}


# ── OWASP Noir ─────────────────────────────────────────────────────────────


@api.post("/noir/audit")
async def noir_audit(req: NoirAuditRequest):
    scan_id = uuid.uuid4().hex[:12]

    async def run_noir_scan():
        try:
            await _broadcast(
                {
                    "type": "noir_audit_started",
                    "scan_id": scan_id,
                    "path": req.project_path,
                }
            )
            global noir
            if not noir.is_installed():
                raise RuntimeError("OWASP Noir no está instalado. Instalar con: snap install noir o brew install noir")
            loop = asyncio.get_running_loop()
            noir.set_progress_callback(_noir_progress_cb(scan_id, loop))
            output = await loop.run_in_executor(None, noir.scan, req.project_path, req.output_format)
            findings = noir.parse_results(output)
            scan_results[scan_id] = {
                "scan_id": scan_id,
                "status": "completed",
                "project_path": req.project_path,
                "findings": [f.model_dump(mode="json") for f in findings],
                "raw_output": output,
            }
            await _broadcast(
                {
                    "type": "noir_audit_completed",
                    "scan_id": scan_id,
                    "result": scan_results[scan_id],
                }
            )
        except Exception as exc:
            logger.error(f"Noir audit {scan_id} failed: {exc}")
            scan_results[scan_id] = {
                "status": "failed",
                "error": str(exc),
                "project_path": req.project_path,
            }
            await _broadcast({"type": "noir_audit_failed", "scan_id": scan_id, "error": str(exc)})
        finally:
            active_scans.pop(scan_id, None)

    task = asyncio.create_task(run_noir_scan())
    active_scans[scan_id] = task
    return {"scan_id": scan_id, "status": "started", "project_path": req.project_path}


@api.post("/noir/upload")
async def noir_upload(file: UploadFile = File(...)):
    scan_id = uuid.uuid4().hex[:12]

    import io
    import shutil

    base_dir = Path.home() / ".websentinel" / "uploads"
    base_dir.mkdir(parents=True, exist_ok=True)
    upload_dir = base_dir / scan_id
    upload_dir.mkdir(exist_ok=True)

    try:
        content = await file.read()
        is_zip = len(content) > 4 and content[:4] == b"PK\x03\x04"

        if is_zip:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                zf.extractall(str(upload_dir))
        else:
            zip_path = upload_dir / (file.filename or "project.zip")
            zip_path.write_bytes(content)

        items = [p for p in upload_dir.iterdir() if not p.name.startswith(".")]
        if len(items) == 1 and items[0].is_dir():
            project_dir = items[0].resolve()
        else:
            project_dir = upload_dir.resolve()

        logger.info(f"Noir upload: extracted to {project_dir}")

        async def run_upload_scan():
            try:
                await _broadcast(
                    {
                        "type": "noir_audit_started",
                        "scan_id": scan_id,
                        "path": str(project_dir),
                    }
                )
                if not noir.is_installed():
                    raise RuntimeError("OWASP Noir no está instalado.")
                loop = asyncio.get_running_loop()
                noir.set_progress_callback(_noir_progress_cb(scan_id, loop))
                output = await loop.run_in_executor(None, noir.scan, str(project_dir), "json")
                findings = noir.parse_results(output)
                scan_results[scan_id] = {
                    "scan_id": scan_id,
                    "status": "completed",
                    "project_path": str(project_dir),
                    "findings": [f.model_dump(mode="json") for f in findings],
                    "raw_output": output,
                }
                await _broadcast(
                    {
                        "type": "noir_audit_completed",
                        "scan_id": scan_id,
                        "result": scan_results[scan_id],
                    }
                )
            except Exception as exc:
                logger.error(f"Noir upload scan {scan_id} failed: {exc}")
                scan_results[scan_id] = {
                    "status": "failed",
                    "error": str(exc),
                    "project_path": str(project_dir),
                }
                await _broadcast({"type": "noir_audit_failed", "scan_id": scan_id, "error": str(exc)})
            finally:
                active_scans.pop(scan_id, None)
                shutil.rmtree(upload_dir, ignore_errors=True)

        task = asyncio.create_task(run_upload_scan())
        active_scans[scan_id] = task

        return {
            "scan_id": scan_id,
            "status": "started",
            "project_path": str(project_dir),
            "uploaded": True,
        }

    except Exception as e:
        shutil.rmtree(upload_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail=f"Upload failed: {e}")


@api.get("/noir/check")
async def check_noir():
    return {
        "installed": noir.is_installed(),
        "message": "OWASP Noir está disponible"
        if noir.is_installed()
        else "Noir no está instalado. Instalar con: snap install noir",
    }


@api.get("/projects/find")
async def find_projects():
    home = Path.home()
    search_dirs = [
        home,
        home / "Documentos",
        home / "Documentos" / "Personal",
        home / "Documentos" / "Universidad",
        home / "Documentos" / "Universidad" / "Base de datos",
        home / "projects",
        home / "dev",
        Path(".").resolve(),
    ]
    projects = []
    indicators = [
        "package.json",
        "pyproject.toml",
        "Cargo.toml",
        "go.mod",
        "Gemfile",
        "requirements.txt",
        "index.html",
        "pom.xml",
        "build.gradle",
    ]
    for sdir in search_dirs:
        if not sdir.is_dir():
            continue
        try:
            for entry in sdir.iterdir():
                if not entry.is_dir() or entry.name.startswith("."):
                    continue
                for ind in indicators:
                    if (entry / ind).exists():
                        projects.append(str(entry))
                        break
        except PermissionError:
            continue
    return {"projects": sorted(set(projects))[:20]}


# ── Report Generation ──────────────────────────────────────────────────────


@api.get("/scan/{scan_id}/report")
async def generate_report(scan_id: str, format: str = Query("html", pattern="^(html|json|markdown)$")):
    result = scan_results.get(scan_id)
    if result is None:
        if scan_id in active_scans:
            raise HTTPException(status_code=400, detail="Scan is still running")
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = result.get("findings", result.get("vulnerabilities", []))
    target = result.get("target", {})
    if isinstance(target, dict):
        target_url = target.get("url", "unknown")
    else:
        target_url = str(target)

    from src.scanner.models import CheckResult, Severity

    check_results = []
    for f in findings:
        if isinstance(f, dict):
            check_results.append(
                CheckResult(
                    name=str(f.get("name", "Unknown")),
                    description=str(f.get("description", "")),
                    severity=Severity(str(f.get("severity", "info"))),
                    url=str(f.get("url", target_url)),
                    evidence=str(f.get("evidence") or ""),
                    remediation=str(f.get("remediation", "")),
                    references=f.get("references") or [],
                )
            )

    report = noir.generate_report(check_results, format)

    if format == "json":
        from fastapi.responses import JSONResponse

        return JSONResponse(json.loads(report) if isinstance(report, str) else report)
    elif format == "markdown":
        return PlainTextResponse(report, media_type="text/markdown")
    else:
        from fastapi.responses import HTMLResponse

        return HTMLResponse(report)


# ── Pipeline Endpoints ──────────────────────────────────────────────────────


@api.post("/pipeline")
async def create_pipeline(req: PipelineRequest):
    pipeline_id = uuid.uuid4().hex[:12]
    steps = req.steps or _build_default_pipeline(req.target)
    state = PipelineState(
        pipeline_id=pipeline_id,
        name=req.name,
        target=req.target,
        status=PipelineStatus.RUNNING,
        steps=[
            StepResult(
                step_id=f"{pipeline_id}_{i}",
                step_type=s.step_type,
                label=s.label,
            )
            for i, s in enumerate(steps)
        ],
    )
    from src.orchestrator.pipeline import active_pipelines, pipeline_tasks

    active_pipelines[pipeline_id] = state

    async def _run():
        try:
            await run_pipeline(req, _broadcast, pipeline_id=pipeline_id, existing_state=state)
            updated = active_pipelines.get(pipeline_id)
            if updated and updated.status == "completed":
                asyncio.create_task(_save_pipeline_to_db(pipeline_id, updated))
        except Exception as e:
            logger.error(f"Pipeline {pipeline_id} failed: {e}")
            if pipeline_id in active_pipelines:
                st = active_pipelines[pipeline_id]
                st.status = "failed"
                st.error = str(e)
            await _broadcast({"type": "pipeline_failed", "pipeline_id": pipeline_id, "error": str(e)})
        finally:
            pipeline_tasks.pop(pipeline_id, None)

    task = asyncio.create_task(_run())
    pipeline_tasks[pipeline_id] = task
    return {
        "pipeline_id": pipeline_id,
        "name": req.name,
        "target": req.target,
        "status": "started",
        "total_steps": len(steps),
    }


@api.get("/pipeline/{pipeline_id}")
async def get_pipeline_status(pipeline_id: str):
    state = get_pipeline(pipeline_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Pipeline not found")
    return state.model_dump(mode="json")


@api.get("/pipelines")
async def list_all_pipelines():
    return {"pipelines": [p.model_dump(mode="json") for p in list_pipelines()]}


@api.delete("/pipeline/{pipeline_id}")
async def cancel_pipeline(pipeline_id: str):
    from src.orchestrator.pipeline import pipeline_tasks

    state = get_pipeline(pipeline_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Pipeline not found")
    if state.status in (PipelineStatus.COMPLETED, PipelineStatus.FAILED, PipelineStatus.CANCELLED):
        return {"status": "already_done", "pipeline_status": state.status}
    task = pipeline_tasks.get(pipeline_id)
    if task and not task.done():
        task.cancel()
    state.status = PipelineStatus.CANCELLED
    return {"status": "cancelled", "pipeline_id": pipeline_id}


# ── Findings Management ────────────────────────────────────────────────────

VALID_STATUSES = {"open", "fixed", "false_positive", "acknowledged"}


class FindingStatusUpdate(BaseModel):
    status: str

    @field_validator("status")
    @classmethod
    def validate_status(cls, v):
        if v not in VALID_STATUSES:
            raise ValueError(f"Invalid status '{v}'. Must be one of: {', '.join(sorted(VALID_STATUSES))}")
        return v


@api.patch("/finding/{finding_id}")
async def update_finding_status(finding_id: str, req: FindingStatusUpdate, db: AsyncSession = Depends(get_db)):
    from sqlalchemy import select

    async with db as session:
        result = await session.execute(select(DBFinding).where(DBFinding.id == finding_id))
        finding = result.scalar_one_or_none()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        old_status: str = finding.status or "open"  # type: ignore[assignment]
        finding.status = req.status  # type: ignore[assignment]
        if req.status == "fixed":
            finding.resolved_at = datetime.now()  # type: ignore[assignment]
        elif old_status != "open" and req.status == "open":
            finding.resolved_at = None  # type: ignore[assignment]
        await session.commit()
        await session.refresh(finding)
    return {"id": finding_id, "status": req.status}


@api.get("/findings")
async def list_findings(
    scan_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    from sqlalchemy import select

    async with db as session:
        q = select(DBFinding)
        if scan_id:
            q = q.where(DBFinding.scan_id == scan_id)
        if status:
            q = q.where(DBFinding.status == status)
        if severity:
            q = q.where(DBFinding.severity == severity)
        result = await session.execute(q)
        findings = result.scalars().all()
    return {
        "total": len(findings),
        "findings": [
            {
                "id": f.id,
                "scan_id": f.scan_id,
                "name": f.name,
                "description": f.description,
                "severity": f.severity,
                "url": f.url,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "references": f.references,
                "source": f.source,
                "status": f.status or "open",
                "resolved_at": f.resolved_at.isoformat() if f.resolved_at else None,
            }
            for f in findings
        ],
    }


@api.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    from sqlalchemy import func, select

    async with db as session:
        total_scans = (await session.execute(select(func.count(DBScan.id)))).scalar() or 0
        total_findings = (await session.execute(select(func.count(DBFinding.id)))).scalar() or 0
        severity_counts = {}
        for sev in ("critical", "high", "medium", "low", "info"):
            cnt = (
                await session.execute(select(func.count(DBFinding.id)).where(DBFinding.severity == sev))
            ).scalar() or 0
            severity_counts[sev] = cnt
        status_counts = {}
        for st in ("open", "fixed", "false_positive", "acknowledged"):
            cnt = (await session.execute(select(func.count(DBFinding.id)).where(DBFinding.status == st))).scalar() or 0
            status_counts[st] = cnt
    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "severity_counts": severity_counts,
        "status_counts": status_counts,
    }


@api.post("/ai/remediation-plan/{scan_id}")
async def generate_remediation_plan(scan_id: str):
    result = scan_results.get(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = result.get("findings", result.get("vulnerabilities", []))
    if not findings:
        return {"plan": [], "message": "No findings to generate plan"}

    sorted_findings = sorted(
        findings,
        key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.get("severity", "info"), 5),
    )
    plan = []
    for f in sorted_findings[:20]:
        remediation = f.get("ai_remediation") or f.get("remediation", "")
        plan.append(
            {
                "name": f.get("name", "Unknown"),
                "severity": f.get("severity", "info"),
                "url": f.get("url", ""),
                "remediation": remediation,
                "priority": {
                    "critical": "Immediate",
                    "high": "Urgent",
                    "medium": "Normal",
                    "low": "Low",
                    "info": "Informational",
                }.get(f.get("severity", "info"), "Low"),
            }
        )

    return {"plan": plan, "total": len(plan), "scan_id": scan_id}


@api.get("/pipeline/{pipeline_id}/report")
async def pipeline_report(pipeline_id: str, format: str = Query("json")):
    state = get_pipeline(pipeline_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Pipeline not found")

    all_findings = []
    step_summaries = []
    for s in state.steps:
        if s.result:
            findings = s.result.get(
                "findings",
                s.result.get("vulnerabilities", s.result.get("enriched_findings", [])),
            )
            all_findings.extend(findings)
            step_summaries.append(
                {
                    "step": s.label,
                    "type": s.step_type.value if hasattr(s.step_type, "value") else str(s.step_type),
                    "status": s.status.value if hasattr(s.status, "value") else str(s.status),
                    "finding_count": s.finding_count,
                    "high_finding_count": s.high_finding_count,
                    "error": s.error,
                    "ai_decision": s.ai_decision,
                }
            )

    total = len(all_findings)
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = f.get("severity", "info")
        if sev in severity_counts:
            severity_counts[sev] += 1

    summary: dict[str, int | dict[str, int]] = {
        "total_steps": len(state.steps),
        "completed_steps": sum(1 for s in state.steps if s.status == "completed"),
        "failed_steps": sum(1 for s in state.steps if s.status == "failed"),
        "total_findings": total,
        "severity_counts": severity_counts,
    }
    report: dict[str, Any] = {
        "pipeline_id": pipeline_id,
        "name": state.name,
        "target": state.target,
        "status": state.status.value if hasattr(state.status, "value") else str(state.status),
        "generated_at": datetime.now().isoformat(),
        "duration_seconds": (
            (state.finished_at - state.created_at).total_seconds() if state.finished_at and state.created_at else None
        ),
        "summary": summary,
        "steps": step_summaries,
    }

    if format == "json":
        return report

    if format == "markdown":
        lines = [
            f"# Pipeline Report: {state.name}",
            f"**Target:** {state.target}",
            f"**Status:** {report['summary']['total_steps']} steps, {report['summary']['total_findings']} findings",
            "",
        ]
        lines.append("## Step Summary")
        for ss in step_summaries:
            lines.append(f"- **{ss['step']}** ({ss['type']}): {ss['status']} — {ss['finding_count']} findings")
        lines.append("")
        lines.append("## Severity Breakdown")
        for sev, cnt in severity_counts.items():
            if cnt > 0:
                lines.append(f"- **{sev.upper()}**: {cnt}")
        return PlainTextResponse("\n".join(lines), media_type="text/markdown")

    sev_bars = "".join(
        f"<div style='display:flex;align-items:center;gap:8px;margin:4px 0'><span style='width:80px;font-size:12px;color:#94a3b8'>{sev.upper()}</span><div style='flex:1;height:20px;background:#1e2d45;border-radius:4px;overflow:hidden'><div style='width:{max(1, cnt / max(severity_counts.values(), default=1) * 100)}%;height:100%;background:{'#dc2626' if sev == 'critical' else '#ea580c' if sev == 'high' else '#ca8a04' if sev == 'medium' else '#2563eb' if sev == 'low' else '#52525b'};border-radius:4px'></div></div><span style='width:40px;font-size:12px;color:#e2e8f0;text-align:right'>{cnt}</span></div>"
        for sev, cnt in severity_counts.items()
        if cnt > 0
    )
    steps_html = "".join(
        f"<tr><td style='padding:8px;border-bottom:1px solid #1e2d45;color:#e2e8f0;font-size:13px'>{ss['step']}</td>"
        f"<td style='padding:8px;border-bottom:1px solid #1e2d45;color:#64748b;font-size:12px'>{ss['type']}</td>"
        f"<td style='padding:8px;border-bottom:1px solid #1e2d45'><span style='padding:2px 8px;border-radius:4px;font-size:11px;background:{'rgba(34,197,94,0.1)' if ss['status'] == 'completed' else 'rgba(239,68,68,0.1)'};color:{'#22c55e' if ss['status'] == 'completed' else '#ef4444'}'>{ss['status']}</span></td>"
        f"<td style='padding:8px;border-bottom:1px solid #1e2d45;color:#e2e8f0;font-size:13px;text-align:center'>{ss['finding_count']}</td></tr>"
        for ss in step_summaries
    )

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Pipeline Report - {state.name}</title>
<style>body{{font-family:Inter,sans-serif;background:#0a0e17;color:#e2e8f0;padding:40px;max-width:900px;margin:auto}}
h1{{color:#fff;font-size:24px}}h2{{color:#94a3b8;font-size:16px;margin-top:30px}}
.card{{background:#0f1729;border:1px solid #1e2d45;border-radius:12px;padding:20px;margin:16px 0}}
table{{width:100%;border-collapse:collapse}}td{{padding:8px}}</style></head><body>
<h1>🔍 Pipeline Report: {state.name}</h1>
<div class="card"><p><strong>Target:</strong> {state.target}</p>
<p><strong>Status:</strong> {report["summary"]["total_steps"]} steps, {report["summary"]["total_findings"]} findings</p>
<p><strong>Duration:</strong> {report["duration_seconds"]:.1f}s</p></div>
<h2>Severity Breakdown</h2><div class="card">{sev_bars}</div>
<h2>Steps</h2><div class="card"><table><tr><th style='text-align:left;color:#64748b;font-size:11px;padding:8px;border-bottom:2px solid #1e2d45'>Step</th>
<th style='text-align:left;color:#64748b;font-size:11px;padding:8px;border-bottom:2px solid #1e2d45'>Type</th>
<th style='text-align:left;color:#64748b;font-size:11px;padding:8px;border-bottom:2px solid #1e2d45'>Status</th>
<th style='text-align:center;color:#64748b;font-size:11px;padding:8px;border-bottom:2px solid #1e2d45'>Findings</th></tr>{steps_html}</table></div>
<p style='text-align:center;color:#475569;font-size:11px;margin-top:40px'>Generated by VulnScout • {datetime.now().strftime("%Y-%m-%d %H:%M")}</p>
</body></html>"""
    return HTMLResponse(html)


# ── AI Endpoints ──────────────────────────────────────────────────────────


@api.get("/ai/check")
async def ai_check():
    available = await ai_enricher.is_available()
    return {
        "available": available,
        "model": ai_enricher.client.model if available else None,
        "message": "Ollama is available"
        if available
        else "Ollama not detected. Install from ollama.com and pull a model (e.g. llama3.2)",
    }


@api.post("/ai/enrich/{scan_id}")
async def ai_enrich(scan_id: str):
    result = scan_results.get(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = result.get("findings", result.get("vulnerabilities", []))
    if not findings:
        return {"enriched": False, "message": "No findings to enrich"}

    enriched = await ai_enricher.enrich_findings(findings)
    target = result.get("target", {})
    if isinstance(target, dict):
        target_url = target.get("url", "unknown")
    else:
        target_url = str(target)

    attack_paths = await ai_enricher.generate_attack_paths(enriched, target_url)
    summary = await ai_enricher.generate_summary(enriched, target_url)

    result["findings"] = enriched
    result["ai_summary"] = summary
    result["ai_attack_paths"] = attack_paths

    return {
        "enriched": True,
        "findings": len(enriched),
        "attack_paths": len(attack_paths),
        "summary": bool(summary),
    }


@api.post("/ai/chat")
async def ai_chat_endpoint(req: ChatRequest):
    context = scan_results.get(req.scan_id) if req.scan_id else None
    response = await ai_chat.handle_message(req, context)
    return {"response": response}


@api.get("/ai/attack-paths/{scan_id}")
async def ai_attack_paths(scan_id: str):
    result = scan_results.get(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    paths = result.get("ai_attack_paths", [])
    if not paths:
        return {"attack_paths": [], "graph": {"nodes": [], "edges": []}}

    from src.ai.attack_path import build_attack_graph

    target = result.get("target", {})
    target_url = target.get("url", "unknown") if isinstance(target, dict) else str(target)
    graph = build_attack_graph(paths, target_url)
    return {"attack_paths": paths, "graph": graph}


# ── Router ─────────────────────────────────────────────────────────────────

app.include_router(api)


@app.get("/", response_class=HTMLResponse)
async def root():
    html_path = Path(__file__).parent / "static" / "dashboard.html"
    if html_path.exists():
        return HTMLResponse(html_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>VulnScout API</h1><p>Dashboard at /api/docs</p>")


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    websocket_clients.append(ws)
    try:
        while True:
            data = await ws.receive_text()
            msg = json.loads(data)
            if msg.get("action") == "ping":
                await ws.send_json({"type": "pong"})
    except WebSocketDisconnect:
        websocket_clients.remove(ws)
    except Exception:
        websocket_clients.remove(ws)
