from __future__ import annotations

from src.gui.main import build_layout, _format_results
from src.scanner.models import ScanResult, ScanTarget, ScanStatus, Severity, CheckResult
from datetime import datetime, timedelta


def test_build_layout():
    layout = build_layout()
    assert layout is not None
    assert len(layout) > 0


def test_format_results_empty():
    result = ScanResult(
        scan_id="test-001",
        target=ScanTarget(url="https://example.com"),
        status=ScanStatus.COMPLETED,
        started_at=datetime.now() - timedelta(seconds=10),
        finished_at=datetime.now(),
    )
    output = _format_results(result)
    assert "VULNSCOUT REPORT" in output
    assert "NO VULNERABILITIES FOUND" in output


def test_format_results_with_findings():
    result = ScanResult(
        scan_id="test-002",
        target=ScanTarget(url="https://example.com"),
        status=ScanStatus.COMPLETED,
        started_at=datetime.now() - timedelta(seconds=30),
        finished_at=datetime.now(),
        total_urls_scanned=5,
        vulnerabilities=[
            CheckResult(
                name="Missing X-Frame-Options",
                description="Header is missing",
                severity=Severity.HIGH,
                url="https://example.com",
                remediation="Add X-Frame-Options: DENY",
            ),
        ],
    )
    output = _format_results(result)
    assert "Missing X-Frame-Options" in output
    assert "HIGH" in output
    assert "Add X-Frame-Options: DENY" in output
