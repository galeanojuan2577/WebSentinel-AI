from __future__ import annotations

import asyncio
import threading
import queue
import os
from datetime import datetime

import FreeSimpleGUI as sg

from src.scanner.engine import ScanEngine
from src.scanner.models import ScanTarget
from src.scanner.reporter import Reporter

SEVERITY_COLORS = {
    "critical": ("#dc2626", "CRITICAL"),
    "high": ("#ea580c", "HIGH"),
    "medium": ("#ca8a04", "MEDIUM"),
    "low": ("#2563eb", "LOW"),
    "info": ("#6b7280", "INFO"),
}

sg.theme("DarkBlue3")


def build_layout():
    return [
        [sg.Text("VulnScout", font=("Helvetica", 18, "bold"), text_color="#2d5a87")],
        [sg.Text("Web Vulnerability Scanner", font=("Helvetica", 10), text_color="#6b7280")],
        [sg.HorizontalSeparator()],
        [
            sg.Text("Target URL:", font=("Helvetica", 11)),
            sg.Input(key="-URL-", font=("Helvetica", 11), expand_x=True),
            sg.Button("Start Scan", key="-SCAN-", font=("Helvetica", 11, "bold"), button_color=("white", "#2563eb")),
        ],
        [sg.HorizontalSeparator()],
        [
            sg.Text("Status:", font=("Helvetica", 10, "bold")),
            sg.Text("Ready", key="-STATUS-", font=("Helvetica", 10)),
        ],
        [
            sg.ProgressBar(100, orientation="h", size=(40, 16), key="-PROGRESS-", visible=False),
        ],
        [sg.HorizontalSeparator()],
        [
            sg.Text("Results", font=("Helvetica", 12, "bold")),
            sg.Push(),
            sg.Button("Save Report", key="-SAVE-", font=("Helvetica", 10), visible=False, button_color=("white", "#059669")),
            sg.Button("Clear", key="-CLEAR-", font=("Helvetica", 10)),
        ],
        [sg.Multiline(key="-RESULTS-", font=("Courier", 10), size=(100, 25), expand_x=True, expand_y=True, autoscroll=True)],
        [sg.HorizontalSeparator()],
        [sg.Text("VulnScout v0.1.0", font=("Helvetica", 8), text_color="#9ca3af")],
    ]


class ScanWorker:
    def __init__(self, url: str, result_queue: queue.Queue):
        self.url = url
        self.result_queue = result_queue
        self._thread: threading.Thread | None = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        async def _scan():
            engine = ScanEngine()
            target = ScanTarget(url=self.url)
            return await engine.run_scan(target)

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(_scan())
            loop.close()
            self.result_queue.put(("done", result))
        except Exception as exc:
            self.result_queue.put(("error", str(exc)))


def _format_results(result) -> str:
    lines: list[str] = []
    summary = result.summary
    total = sum(summary.values())

    lines.append(f"{'='*60}")
    lines.append(f"  VULNSCOUT REPORT")
    lines.append(f"  Target: {result.target.url}")
    lines.append(f"  Scan ID: {result.scan_id}")
    if result.duration_seconds is not None:
        lines.append(f"  Duration: {result.duration_seconds:.1f}s")
    lines.append(f"  URLs Scanned: {result.total_urls_scanned}")
    lines.append(f"  Total Findings: {total}")
    lines.append(f"{'='*60}")
    lines.append("")

    lines.append("  SUMMARY")
    lines.append(f"  {'─'*40}")
    severity_order = ["critical", "high", "medium", "low", "info"]
    for sev in severity_order:
        count = summary.get(sev, 0)
        _, label = SEVERITY_COLORS.get(sev, ("", sev.upper()))
        lines.append(f"    {label:10s} → {count}")
    lines.append("")

    if total == 0:
        lines.append("  ✓ NO VULNERABILITIES FOUND")
        lines.append("")

    for i, v in enumerate(result.vulnerabilities, 1):
        color, label = SEVERITY_COLORS.get(v.severity.value, ("#6b7280", v.severity.value.upper()))
        lines.append(f"  {'─'*60}")
        lines.append(f"  [{label}] {v.name}")
        lines.append(f"  URL: {v.url}")
        lines.append(f"  {v.description}")
        lines.append("")
        if v.evidence:
            lines.append(f"  Evidence:")
            lines.append(f"    {v.evidence}")
            lines.append("")
        lines.append(f"  Remediation:")
        for line in v.remediation.strip().split("\n"):
            lines.append(f"    {line.strip()}")
        lines.append("")
        if v.references:
            lines.append(f"  References:")
            for ref in v.references:
                lines.append(f"    {ref}")
        lines.append("")

    return "\n".join(lines)


def main():
    sg.set_options(font=("Helvetica", 10))
    window = sg.Window(
        "VulnScout",
        build_layout(),
        size=(900, 700),
        resizable=True,
        finalize=True,
    )

    result_queue: queue.Queue = queue.Queue()
    scan_worker: ScanWorker | None = None

    while True:
        event, values = window.read(timeout=100)

        if event == sg.WIN_CLOSED:
            break

        if event == "-SCAN-":
            url = values["-URL-"].strip()
            if not url:
                sg.popup_error("Please enter a target URL")
                continue
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
                window["-URL-"].update(url)

            window["-RESULTS-"].update("")
            window["-STATUS-"].update("Scanning...")
            window["-PROGRESS-"].update(0, visible=True)
            window["-SCAN-"].update(disabled=True, text="Scanning...")
            window["-SAVE-"].update(visible=False)
            window.refresh()

            scan_worker = ScanWorker(url, result_queue)
            scan_worker.start()

        if event == "-CLEAR-":
            window["-RESULTS-"].update("")
            window["-STATUS-"].update("Ready")
            window["-PROGRESS-"].update(0, visible=False)
            window["-SAVE-"].update(visible=False)
            window["-SCAN-"].update(disabled=False, text="Start Scan")

        if event == "-SAVE-":
            result_text = window["-RESULTS-"].get()
            if result_text.strip():
                default_name = f"websentinel_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                filename = sg.popup_get_file(
                    "Save Report",
                    save_as=True,
                    default_extension=".txt",
                    initial_filename=default_name,
                    file_types=(("Text files", "*.txt"), ("All files", "*.*")),
                )
                if filename:
                    try:
                        with open(filename, "w", encoding="utf-8") as f:
                            f.write(result_text)
                        sg.popup_ok(f"Report saved to:\n{filename}")
                    except Exception as e:
                        sg.popup_error(f"Failed to save report: {e}")

        try:
            msg = result_queue.get_nowait()
            if msg[0] == "done":
                result = msg[1]
                output = _format_results(result)
                window["-RESULTS-"].update(output)
                window["-STATUS-"].update(f"Completed — {len(result.vulnerabilities)} findings")
                window["-PROGRESS-"].update(100)
                window["-SAVE-"].update(visible=True)
            elif msg[0] == "error":
                window["-RESULTS-"].update(f"ERROR: {msg[1]}")
                window["-STATUS-"].update("Failed")
                window["-PROGRESS-"].update(0, visible=False)
            window["-SCAN-"].update(disabled=False, text="Start Scan")
        except queue.Empty:
            pass

    window.close()


if __name__ == "__main__":
    main()
