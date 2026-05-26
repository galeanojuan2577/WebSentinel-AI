from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, HttpUrl


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CheckResult(BaseModel):
    name: str
    description: str
    severity: Severity
    url: str
    evidence: Optional[str] = None
    remediation: str
    references: list[str] = []


class ScanTarget(BaseModel):
    url: str
    checks: list[str] = ["all"]
    max_pages: int = Field(default=10, ge=1, le=100)
    follow_redirects: bool = True


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    target: ScanTarget
    status: ScanStatus = ScanStatus.PENDING
    started_at: datetime = Field(default_factory=datetime.now)
    finished_at: Optional[datetime] = None
    vulnerabilities: list[CheckResult] = []
    total_urls_scanned: int = 0
    error: Optional[str] = None

    @property
    def duration_seconds(self) -> float | None:
        if self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for v in self.vulnerabilities:
            counts[v.severity.value] += 1
        return counts
