from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Optional

import httpx

from src.scanner.checks.base import BaseCheck
from src.scanner.checks.headers import HeadersCheck
from src.scanner.checks.ssl import SSLCheck
from src.scanner.checks.xss import XSSCheck
from src.scanner.checks.sqli import SQLICheck
from src.scanner.checks.directories import DirectoriesCheck
from src.scanner.checks.cookies import CookiesCheck
from src.scanner.checks.tech import TechDetectCheck
from src.scanner.models import ScanResult, ScanTarget, ScanStatus

logger = logging.getLogger("websentinel.engine")

_DEFAULT_CHECKS: list[type[BaseCheck]] = [
    HeadersCheck,
    SSLCheck,
    XSSCheck,
    SQLICheck,
    DirectoriesCheck,
    CookiesCheck,
    TechDetectCheck,
]

try:
    from src.scanner.checks.dns import DNSCheck
    _DEFAULT_CHECKS.append(DNSCheck)
except ImportError:
    pass

try:
    from src.scanner.checks.wifi import WiFiScanCheck
    _DEFAULT_CHECKS.append(WiFiScanCheck)
except Exception:
    pass

_USER_AGENT = "WebSentinel-AI/0.3 (Security Scanner; https://github.com/galeanojuan2577/WebSentinel-AI)"


class ScanEngine:
    def __init__(self, checks: Optional[list[type[BaseCheck]]] = None):
        self._check_classes = checks or _DEFAULT_CHECKS

    async def run_scan(self, target: ScanTarget) -> ScanResult:
        result = ScanResult(
            target=target,
            status=ScanStatus.RUNNING,
            started_at=datetime.now(),
        )

        timeout = httpx.Timeout(
            connect=30.0,
            read=30.0,
            write=30.0,
            pool=60.0,
        )

        limits = httpx.Limits(
            max_keepalive_connections=10,
            max_connections=20,
        )

        async with httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            follow_redirects=target.follow_redirects,
            headers={"User-Agent": _USER_AGENT},
            verify=False,
        ) as client:
            check_instances = [cls() for cls in self._check_classes]

            selected = [
                c for c in check_instances
                if "all" in target.checks or c.name in target.checks
            ]

            if not selected:
                result.status = ScanStatus.FAILED
                result.error = f"No checks matched the filter: {target.checks}"
                result.finished_at = datetime.now()
                return result

            for check in selected:
                logger.info("Running check: %s on %s", check.name, target.url)
                try:
                    findings = await check.run(target.url, client)
                    result.vulnerabilities.extend(findings)
                    result.total_urls_scanned += 1
                    logger.info("Check %s completed: %d findings", check.name, len(findings))
                except Exception as exc:
                    logger.error("Check %s failed: %s", check.name, exc, exc_info=True)
                    from src.scanner.models import CheckResult, Severity
                    result.vulnerabilities.append(CheckResult(
                        name=f"Check Error: {check.name}",
                        description=f"El check '{check.name}' falló con error: {exc}",
                        severity=Severity.INFO,
                        url=target.url,
                        remediation="Revisar los logs para más detalles.",
                    ))

        result.status = ScanStatus.COMPLETED
        result.finished_at = datetime.now()

        result.vulnerabilities.sort(
            key=lambda v: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                    v.severity.value, 5
                )
            )
        )

        return result

    def list_checks(self) -> list[dict[str, str]]:
        return [
            {"name": cls.name, "description": cls.description}
            for cls in self._check_classes
        ]
