from __future__ import annotations

import argparse
import asyncio
import os
import sys
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from src.scanner.engine import ScanEngine
from src.scanner.models import ScanStatus, ScanTarget, Severity
from src.scanner.reporter import Reporter

console = Console()

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold orange3",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold blue",
    Severity.INFO: "dim white",
}


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="websentinel",
        description="Professional web vulnerability scanner with actionable remediation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  websentinel https://example.com
  websentinel https://example.com --checks security_headers,xss
  websentinel https://example.com --output report.html --format html
  websentinel --list-checks
        """,
    )

    parser.add_argument("url", nargs="?", help="Target URL to scan")
    parser.add_argument("--checks", "-c", help="Comma-separated list of checks to run (default: all)")
    parser.add_argument("--output", "-o", help="Output file path for the report")
    parser.add_argument(
        "--format",
        "-f",
        choices=["html", "json", "markdown"],
        default="html",
        help="Report format (default: html)",
    )
    parser.add_argument(
        "--list-checks",
        "-l",
        action="store_true",
        help="List available checks and exit",
    )
    parser.add_argument("--max-pages", type=int, default=10, help="Maximum pages to scan (default: 10)")
    parser.add_argument("--no-redirect", action="store_true", help="Do not follow redirects")
    parser.add_argument("--version", "-v", action="version", version="VulnScout 0.1.0")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress banner and progress")

    return parser.parse_args(argv)


def _print_banner():
    banner = """
╔══════════════════════════════════════════════╗
║           VulnScout v0.1.0                  ║
║     Web Vulnerability Scanner               ║
║     github.com/galeanojuan2577/WebSentinel-AI    ║
╚══════════════════════════════════════════════╝
"""
    console.print(banner, style="bold blue")


def _list_checks():
    engine = ScanEngine()
    table = Table(title="Available Checks", show_header=True, header_style="bold cyan")
    table.add_column("Name", style="cyan")
    table.add_column("Description")

    for check in engine.list_checks():
        table.add_row(check["name"], check["description"])

    console.print(table)


def _print_results(result):
    summary = result.summary
    total = len(result.vulnerabilities)

    if total == 0:
        console.print(Panel("[bold green]No vulnerabilities found![/]", title="Result"))
        return

    summary_table = Table(title="Summary", show_header=True, header_style="bold")
    summary_table.add_column("Severity", style="bold")
    summary_table.add_column("Count", justify="right")

    severity_order = [
        (Severity.CRITICAL, "Critical"),
        (Severity.HIGH, "High"),
        (Severity.MEDIUM, "Medium"),
        (Severity.LOW, "Low"),
        (Severity.INFO, "Info"),
    ]

    for sev, label in severity_order:
        count = summary.get(sev.value, 0)
        style = SEVERITY_STYLES.get(sev, "")
        summary_table.add_row(f"[{style}]{label}[/]", f"[{style}]{count}[/]")

    console.print()
    console.print(summary_table)
    console.print()

    for i, v in enumerate(result.vulnerabilities, 1):
        style = SEVERITY_STYLES.get(v.severity, "")
        label = v.severity.value.upper()

        content = Text()
        content.append(f"\n[{style}]{label}[/] ", style=style)
        content.append(f"{v.name}\n", style="bold")
        content.append(f"  URL: {v.url}\n", style="dim")
        content.append(f"  {v.description}\n")

        if v.evidence:
            content.append(f"  Evidence: {v.evidence}\n", style="italic")

        content.append("\n  Remediation:\n", style="bold green")
        for line in v.remediation.split("\n"):
            content.append(f"    {line}\n")

        if v.references:
            content.append("\n  References:\n", style="dim")
            for ref in v.references:
                content.append(f"    {ref}\n")

        console.print(Panel(content, border_style=style.split()[-1] if style else "white"))


def _generate_report(result, output_path: str, fmt: str) -> None:
    reporter = Reporter()

    if fmt == "json":
        content = reporter.generate_json(result)
    elif fmt == "markdown":
        content = reporter.generate_markdown(result)
    else:
        content = reporter.generate_html(result)

    if output_path:
        output_dir = os.path.dirname(output_path)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        console.print(f"\n[bold green]Report saved to:[/] {output_path}")
    else:
        default_name = f"websentinel_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}"
        os.makedirs("reports", exist_ok=True)
        output_path = os.path.join("reports", default_name)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        console.print(f"\n[bold green]Report saved to:[/] {output_path}")


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)

    if args.list_checks:
        _list_checks()
        return 0

    if not args.url:
        console.print("[bold red]Error:[/] URL is required. Use --help for usage.")
        return 1

    if not args.quiet:
        _print_banner()

    target = ScanTarget(
        url=args.url,
        checks=args.checks.split(",") if args.checks else ["all"],
        max_pages=args.max_pages,
        follow_redirects=not args.no_redirect,
    )

    if not args.quiet:
        console.print(f"[bold]Target:[/] {target.url}")
        console.print(f"[bold]Checks:[/] {', '.join(target.checks)}")
        console.print()

    engine = ScanEngine()

    async def _run():
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
            transient=False,
        ) as progress:
            task = progress.add_task(f"Scanning {target.url}...", total=len(engine.list_checks()))

            result = await engine.run_scan(target)

            check_names = engine.list_checks()
            for i, _ in enumerate(check_names):
                progress.update(task, completed=i + 1)

            progress.update(task, completed=len(check_names))

        return result

    try:
        result = asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan interrupted by user.[/]")
        return 130
    except Exception as exc:
        console.print(f"\n[bold red]Scan failed:[/] {exc}")
        return 1

    if not args.quiet:
        console.print(f"\n[bold]Scan completed in {result.duration_seconds:.1f}s[/]")
        console.print(f"[bold]Total URLs scanned:[/] {result.total_urls_scanned}")
        console.print(f"[bold]Vulnerabilities found:[/] {len(result.vulnerabilities)}")

    _print_results(result)

    if args.output or args.format:
        fmt = args.format or "html"
        output = args.output or ""
        _generate_report(result, output, fmt)

    return 0 if result.status == ScanStatus.COMPLETED else 1


if __name__ == "__main__":
    sys.exit(main())
