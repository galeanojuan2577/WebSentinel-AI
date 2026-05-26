from __future__ import annotations

import json
from datetime import datetime
from typing import Optional

from src.scanner.models import ScanResult, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#ca8a04",
    Severity.LOW: "#2563eb",
    Severity.INFO: "#6b7280",
}

SEVERITY_LABELS = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}


class Reporter:
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = output_dir

    def generate_json(self, result: ScanResult) -> str:
        return json.dumps(
            result.model_dump(mode="json"),
            indent=2,
            ensure_ascii=False,
        )

    def generate_markdown(self, result: ScanResult) -> str:
        lines: list[str] = [
            f"# VulnScout Report — {result.target.url}",
            f"",
            f"**Scan ID**: {result.scan_id}",
            f"**Started**: {result.started_at.isoformat()}",
            f"**Duration**: {result.duration_seconds:.1f}s" if result.duration_seconds else "**Duration**: N/A",
            f"**Status**: {result.status.value}",
            f"**URLs Scanned**: {result.total_urls_scanned}",
            f"**Total Findings**: {len(result.vulnerabilities)}",
            f"",
            "## Summary",
            f"",
            "| Severity | Count |",
            "|----------|-------|",
        ]

        summary = result.summary
        for sev in Severity:
            lines.append(f"| {sev.value.upper()} | {summary[sev.value]} |")

        lines.extend(["", "## Findings", ""])

        for i, v in enumerate(result.vulnerabilities, 1):
            lines.extend([
                f"### {i}. [{v.severity.value.upper()}] {v.name}",
                f"",
                f"**URL**: {v.url}",
                f"**Description**: {v.description}",
                f"",
                f"**Remediation**:",
                f"```",
                v.remediation,
                f"```",
                f"",
            ])
            if v.evidence:
                lines.extend([
                    f"**Evidence**:",
                    f"```",
                    v.evidence,
                    f"```",
                    f"",
                ])
            if v.references:
                lines.extend([
                    f"**References**:",
                    *[f"- {ref}" for ref in v.references],
                    f"",
                ])

        return "\n".join(lines)

    def generate_html(self, result: ScanResult) -> str:
        summary = result.summary
        findings_rows = ""
        for i, v in enumerate(result.vulnerabilities, 1):
            color = SEVERITY_COLORS.get(v.severity, "#6b7280")
            label = SEVERITY_LABELS.get(v.severity, "INFO")
            evidence_html = ""
            if v.evidence:
                evidence_html = f"""
                <div class="evidence">
                    <strong>Evidence:</strong>
                    <pre>{self._escape(v.evidence)}</pre>
                </div>"""
            refs_html = ""
            if v.references:
                refs_html = "<div class='refs'><strong>References:</strong><ul>" + \
                    "".join(f'<li><a href="{ref}" target="_blank">{ref}</a></li>' for ref in v.references) + \
                    "</ul></div>"

            findings_rows += f"""
            <div class="finding" style="border-left: 4px solid {color}; padding: 16px; margin: 12px 0; background: #f9fafb; border-radius: 4px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <h3 style="margin: 0;">{self._escape(v.name)}</h3>
                    <span class="badge badge-{v.severity.value}" style="background: {color}; color: white; padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: 600;">{label}</span>
                </div>
                <p style="margin: 8px 0 4px;"><strong>URL:</strong> <code>{self._escape(v.url)}</code></p>
                <p style="margin: 4px 0;">{self._escape(v.description)}</p>
                <div class="remediation" style="margin: 8px 0; padding: 8px; background: #fef3c7; border-radius: 4px;">
                    <strong>Remediation:</strong>
                    <pre style="white-space: pre-wrap; margin: 4px 0 0;">{self._escape(v.remediation)}</pre>
                </div>
                {evidence_html}
                {refs_html}
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnScout Report — {self._escape(result.target.url)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f3f4f6; color: #1f2937; padding: 20px; }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #1e3a5f, #2d5a87); color: white; padding: 32px; border-radius: 8px; margin-bottom: 24px; }}
        .header h1 {{ font-size: 24px; margin-bottom: 8px; }}
        .header .meta {{ font-size: 14px; opacity: 0.9; }}
        .summary {{ background: white; padding: 24px; border-radius: 8px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .summary h2 {{ margin-bottom: 16px; color: #1e3a5f; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid #e5e7eb; }}
        th {{ font-weight: 600; color: #6b7280; font-size: 14px; text-transform: uppercase; }}
        .findings {{ margin-top: 24px; }}
        .findings h2 {{ margin-bottom: 16px; color: #1e3a5f; }}
        .finding h3 {{ font-size: 16px; }}
        .finding code {{ background: #e5e7eb; padding: 2px 6px; border-radius: 3px; font-size: 13px; }}
        .evidence pre {{ background: #1f2937; color: #e5e7eb; padding: 12px; border-radius: 4px; overflow-x: auto; font-size: 13px; margin-top: 4px; }}
        .remediation pre {{ font-family: inherit; font-size: 14px; }}
        .refs {{ margin-top: 8px; }}
        .refs ul {{ margin-left: 20px; }}
        .refs a {{ color: #2563eb; font-size: 13px; }}
        .footer {{ text-align: center; color: #9ca3af; font-size: 13px; margin-top: 32px; padding: 16px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>VulnScout Report</h1>
            <div class="meta">
                <p><strong>Target:</strong> {self._escape(result.target.url)}</p>
                <p><strong>Scan ID:</strong> {self._escape(result.scan_id)}</p>
                <p><strong>Date:</strong> {result.started_at.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p><strong>Duration:</strong> {result.duration_seconds:.1f}s</p>
                <p><strong>Findings:</strong> {len(result.vulnerabilities)}</p>
            </div>
        </div>

        <div class="summary">
            <h2>Summary</h2>
            <table>
                <tr><th>Severity</th><th>Count</th></tr>
                <tr><td style="color: #dc2626; font-weight: 600;">Critical</td><td>{summary['critical']}</td></tr>
                <tr><td style="color: #ea580c; font-weight: 600;">High</td><td>{summary['high']}</td></tr>
                <tr><td style="color: #ca8a04; font-weight: 600;">Medium</td><td>{summary['medium']}</td></tr>
                <tr><td style="color: #2563eb; font-weight: 600;">Low</td><td>{summary['low']}</td></tr>
                <tr><td style="color: #6b7280; font-weight: 600;">Info</td><td>{summary['info']}</td></tr>
            </table>
        </div>

        <div class="findings">
            <h2>Findings</h2>
            {findings_rows}
        </div>

        <div class="footer">
            <p>Generated by VulnScout — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>"""

    @staticmethod
    def _escape(text: str) -> str:
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
