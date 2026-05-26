from __future__ import annotations

from src.scanner.models import ScanResult, ScanTarget, ScanStatus, Severity, CheckResult
from src.scanner.reporter import Reporter


def test_reporter_json():
    result = _make_sample_result()
    reporter = Reporter()
    json_str = reporter.generate_json(result)
    assert '"scan_id"' in json_str
    assert '"vulnerabilities"' in json_str
    assert '"Missing X-Frame-Options"' in json_str


def test_reporter_markdown():
    result = _make_sample_result()
    reporter = Reporter()
    md = reporter.generate_markdown(result)
    assert "VulnScout Report" in md
    assert "CRITICAL" in md
    assert "Missing X-Frame-Options" in md


def test_reporter_html():
    result = _make_sample_result()
    reporter = Reporter()
    html = reporter.generate_html(result)
    assert "VulnScout Report" in html
    assert "HIGH" in html
    assert "Missing X-Frame-Options" in html


def test_reporter_escape():
    assert Reporter._escape("<script>") == "&lt;script&gt;"
    assert Reporter._escape('"quoted"') == "&quot;quoted&quot;"


def _make_sample_result() -> ScanResult:
    from datetime import datetime, timedelta
    return ScanResult(
        scan_id="test-001",
        target=ScanTarget(url="https://example.com"),
        status=ScanStatus.COMPLETED,
        started_at=datetime.now() - timedelta(seconds=30),
        finished_at=datetime.now(),
        total_urls_scanned=5,
        vulnerabilities=[
            CheckResult(
                name="Missing X-Frame-Options",
                description="X-Frame-Options header is missing.",
                severity=Severity.HIGH,
                url="https://example.com",
                remediation="Add X-Frame-Options: DENY",
                references=["https://example.com/ref"],
            ),
            CheckResult(
                name="Open Port: 8080",
                description="Port 8080 is open.",
                severity=Severity.MEDIUM,
                url="https://example.com:8080",
                evidence="Port: 8080",
                remediation="Close port 8080 if not needed.",
            ),
        ],
    )
