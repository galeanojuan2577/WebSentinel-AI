from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field

from src.ai.ollama import OllamaClient
from src.scanner.engine import ScanEngine
from src.scanner.models import ScanTarget, ScanResult as EngineScanResult

logger = logging.getLogger("websentinel.orchestrator")


class StepType(str, Enum):
    WEB_SCAN = "web_scan"
    LINK_SCAN = "link_scan"
    NETWORK_SCAN = "network_scan"
    NOIR_AUDIT = "noir_audit"
    AI_ENRICH = "ai_enrich"
    AI_DECISION = "ai_decision"


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class PipelineStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PipelineStepConfig(BaseModel):
    step_type: StepType
    label: str
    params: dict[str, Any] = Field(default_factory=dict)
    ai_gate: bool = False


class PipelineRequest(BaseModel):
    name: str
    target: str
    steps: list[PipelineStepConfig] = Field(default_factory=list)


class StepResult(BaseModel):
    step_id: str
    step_type: StepType
    label: str
    status: StepStatus = StepStatus.PENDING
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    result: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    ai_decision: Optional[str] = None
    summary: Optional[dict[str, int]] = None
    finding_count: int = 0
    high_finding_count: int = 0


class PipelineState(BaseModel):
    pipeline_id: str
    name: str
    target: str
    status: PipelineStatus = PipelineStatus.PENDING
    steps: list[StepResult] = Field(default_factory=list)
    current_step_index: int = -1
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None
    error: Optional[str] = None


active_pipelines: dict[str, PipelineState] = {}
pipeline_tasks: dict[str, asyncio.Task] = {}


async def _run_step(
    step: StepResult,
    target: str,
    broadcast: callable,
    previous_result: Optional[StepResult] = None,
) -> None:
    step.status = StepStatus.RUNNING
    step.started_at = datetime.now(timezone.utc)
    await broadcast({
        "type": "pipeline_step_started",
        "pipeline_id": step.step_id.rsplit("_", 1)[0] if "_" in step.step_id else "",
        "step_id": step.step_id,
        "step_type": step.step_type.value,
        "label": step.label,
    })

    try:
        if step.step_type == StepType.WEB_SCAN:
            checks = step.result.get("checks", ["all"]) if step.result else ["all"]
            engine = ScanEngine()
            scan_target = ScanTarget(
                url=target,
                checks=checks,
                max_pages=step.result.get("max_pages", 10) if step.result else 10,
            )
            result = await engine.run_scan(scan_target)
            data = result.model_dump(mode="json")
            step.result = data
            step.summary = result.summary
            step.finding_count = len(result.vulnerabilities)
            step.high_finding_count = sum(
                1 for v in result.vulnerabilities if v.severity in ("critical", "high")
            )

        elif step.step_type == StepType.LINK_SCAN:
            from src.scanner.comprehensive import run_comprehensive_scan
            result = await run_comprehensive_scan(target)
            step.result = result
            findings = result.get("findings", [])
            step.finding_count = len(findings)
            step.high_finding_count = sum(
                1 for f in findings if f.get("severity") in ("critical", "high")
            )

        elif step.step_type == StepType.AI_ENRICH:
            ollama = OllamaClient()
            scan_data = step.result or {}
            findings = scan_data.get("vulnerabilities", scan_data.get("findings", []))
            enriched = []
            for f in findings:
                analysis = await ollama.analyze_vulnerability(f)
                remediation = await ollama.generate_remediation(f)
                enriched.append({**f, "ai_analysis": analysis, "ai_remediation": remediation})
            step.result = {
                "enriched_findings": enriched,
                "total": len(enriched),
            }

        elif step.step_type == StepType.AI_DECISION:
            ollama = OllamaClient()
            ctx_data = (previous_result.result or {}) if previous_result else (step.result or {})
            findings_preview = ""
            for key in ("findings", "vulnerabilities", "enriched_findings"):
                items = ctx_data.get(key, [])
                if items:
                    total = len(items)
                    high = sum(1 for f in items if f.get("severity") in ("critical", "high"))
                    findings_preview = f" ({total} findings, {high} high/critical)"
                    break
            prompt = (
                f"Based on scan results for target {target}{findings_preview}, "
                f"decide the next penetration testing step. "
                f"Respond with ONLY valid JSON: {{\"decision\": \"continue|stop\", "
                f"\"reason\": \"...\", \"next_step_type\": \"web_scan|link_scan|network_scan|noir_audit|null\"}}"
            )
            try:
                decision = await asyncio.wait_for(ollama._call(prompt), timeout=30)
            except asyncio.TimeoutError:
                decision = ""
                logger.warning(f"AI Decision timeout for step {step.step_id}")
            try:
                parsed = json.loads(decision) if decision else {}
                step.ai_decision = parsed.get("decision", "continue")
                step.result = {
                    "ai_decision": parsed.get("decision", "continue"),
                    "reason": parsed.get("reason", "AI decision timeout or unparseable"),
                    "next_step_type": parsed.get("next_step_type"),
                }
            except (json.JSONDecodeError, TypeError):
                step.ai_decision = "continue"
                step.result = {"ai_decision": "continue", "reason": "AI response unparseable"}

        else:
            step.result = {"note": f"Step type {step.step_type} not implemented"}
            step.finding_count = 0
            step.high_finding_count = 0

        step.status = StepStatus.COMPLETED
        step.finished_at = datetime.now(timezone.utc)
        await broadcast({
            "type": "pipeline_step_completed",
            "pipeline_id": step.step_id.rsplit("_", 1)[0] if "_" in step.step_id else "",
            "step_id": step.step_id,
            "step_type": step.step_type.value,
            "label": step.label,
            "summary": step.summary,
            "finding_count": step.finding_count,
            "high_finding_count": step.high_finding_count,
        })

    except Exception as e:
        logger.error(f"Pipeline step {step.step_id} failed: {e}")
        step.status = StepStatus.FAILED
        step.error = str(e)
        step.finished_at = datetime.now(timezone.utc)
        await broadcast({
            "type": "pipeline_step_failed",
            "pipeline_id": step.step_id.rsplit("_", 1)[0] if "_" in step.step_id else "",
            "step_id": step.step_id,
            "error": str(e),
        })


async def _ai_gate_check(
    step_config: PipelineStepConfig,
    previous_step: StepResult,
    ollama: OllamaClient,
    target: str,
    broadcast: callable,
) -> bool:
    context = previous_step.result or {}
    prompt = (
        f"Given these results from {previous_step.step_type} on {target}, "
        f"should we run {step_config.step_type} next? "
        f"Context: {json.dumps(context, indent=2)[:2000]}\n\n"
        f"Respond JSON: {{\"run\": true|false, \"reason\": \"...\"}}"
    )
    try:
        resp = await ollama._call(prompt)
        parsed = json.loads(resp)
        decision = parsed.get("run", False)
        reason = parsed.get("reason", "")
        logger.info(f"AI gate for {step_config.step_type}: run={decision}, reason={reason}")
        return bool(decision)
    except Exception:
        logger.warning(f"AI gate check failed for {step_config.step_type}, defaulting to run")
        return True


def _build_default_pipeline(target: str) -> list[PipelineStepConfig]:
    return [
        PipelineStepConfig(
            step_type=StepType.WEB_SCAN,
            label="Web Vulnerability Scan",
            params={"checks": ["all"], "max_pages": 10},
        ),
        PipelineStepConfig(
            step_type=StepType.AI_ENRICH,
            label="AI Analysis of Web Findings",
            params={},
        ),
        PipelineStepConfig(
            step_type=StepType.AI_DECISION,
            label="AI Decision: Next Action",
            params={},
        ),
        PipelineStepConfig(
            step_type=StepType.LINK_SCAN,
            label="Comprehensive Link Analysis",
            params={},
        ),
        PipelineStepConfig(
            step_type=StepType.AI_ENRICH,
            label="AI Analysis of Link Findings",
            params={},
        ),
        PipelineStepConfig(
            step_type=StepType.AI_DECISION,
            label="AI Decision: Final Assessment",
            params={},
        ),
    ]


async def run_pipeline(
    request: PipelineRequest,
    broadcast: callable,
    pipeline_id: Optional[str] = None,
    existing_state: Optional[PipelineState] = None,
) -> str:
    pipeline_id = pipeline_id or uuid.uuid4().hex[:12]

    steps = request.steps or _build_default_pipeline(request.target)
    state = existing_state or PipelineState(
        pipeline_id=pipeline_id,
        name=request.name,
        target=request.target,
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
    if not existing_state:
        state.status = PipelineStatus.RUNNING
        state.steps = [
            StepResult(
                step_id=f"{pipeline_id}_{i}",
                step_type=s.step_type,
                label=s.label,
            )
            for i, s in enumerate(steps)
        ]
    active_pipelines[pipeline_id] = state

    await broadcast({
        "type": "pipeline_started",
        "pipeline_id": pipeline_id,
        "name": request.name,
        "target": request.target,
        "total_steps": len(steps),
    })

    ollama = OllamaClient()
    previous_result: Optional[StepResult] = None

    for i, step_config in enumerate(steps):
        step_result = state.steps[i]

        if step_config.ai_gate and previous_result:
            should_run = await _ai_gate_check(
                step_config, previous_result, ollama, request.target, broadcast
            )
            if not should_run:
                step_result.status = StepStatus.SKIPPED
                step_result.ai_decision = "Skipped by AI gate"
                await broadcast({
                    "type": "pipeline_step_skipped",
                    "pipeline_id": pipeline_id,
                    "step_id": step_result.step_id,
                    "label": step_result.label,
                    "reason": step_result.ai_decision,
                })
                previous_result = step_result
                continue

        state.current_step_index = i
        if step_config.params:
            step_result.result = step_config.params
        await _run_step(step_result, request.target, broadcast, previous_result)

        if step_result.status == StepStatus.FAILED:
            state.status = PipelineStatus.FAILED
            state.error = f"Step {step_result.label} failed: {step_result.error}"
            state.finished_at = datetime.now(timezone.utc)
            await broadcast({
                "type": "pipeline_failed",
                "pipeline_id": pipeline_id,
                "error": state.error,
            })
            return pipeline_id

        previous_result = step_result

    state.status = PipelineStatus.COMPLETED
    state.finished_at = datetime.now(timezone.utc)
    await broadcast({
        "type": "pipeline_completed",
        "pipeline_id": pipeline_id,
        "name": request.name,
        "total_steps": len(steps),
    })

    return pipeline_id


def get_pipeline(pipeline_id: str) -> Optional[PipelineState]:
    return active_pipelines.get(pipeline_id)


def list_pipelines() -> list[PipelineState]:
    return list(active_pipelines.values())
