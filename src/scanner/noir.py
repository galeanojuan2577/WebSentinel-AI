from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from src.scanner.models import CheckResult, Severity

logger = logging.getLogger("websentinel.noir")


class NoirScanner:
    """Wrapper para ejecutar OWASP Noir con progreso en tiempo real."""

    def __init__(self, noir_path: str = "noir"):
        self.noir_path = noir_path
        self._progress_callback: Optional[Callable[[int, str], None]] = None

    def set_progress_callback(self, cb: Callable[[int, str], None]):
        self._progress_callback = cb

    def _progress(self, percent: int, msg: str):
        if self._progress_callback:
            self._progress_callback(percent, msg)

    def is_installed(self) -> bool:
        return shutil.which(self.noir_path) is not None

    def extract_zip(self, zip_path: str, target_dir: Optional[str] = None) -> str:
        if target_dir is None:
            ext_dir = tempfile.mkdtemp(prefix="websentinel_noir_")
        else:
            ext_dir = target_dir

        extract_to = os.path.join(ext_dir, "src")
        os.makedirs(extract_to, exist_ok=True)

        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(extract_to)

        if os.path.isfile(zip_path):
            os.remove(zip_path)

        items = [i for i in os.listdir(extract_to) if not i.startswith(".")]
        if len(items) == 1 and os.path.isdir(os.path.join(extract_to, items[0])):
            return os.path.join(extract_to, items[0])
        return extract_to

    def _run_noir(self, project_path: str, output_format: str) -> subprocess.CompletedProcess:
        cmd = [self.noir_path, "-b", project_path, "-f", output_format]
        logger.info(f"Ejecutando Noir: {' '.join(cmd)}")
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
            cwd=project_path,
        )

    def _extract_archive(self, path: str) -> str | None:
        ext = path.lower()
        base_dir = os.path.join(os.path.expanduser("~"), ".websentinel", "extractions")
        os.makedirs(base_dir, exist_ok=True)
        out_dir = tempfile.mkdtemp(prefix="extract_", dir=base_dir)

        try:
            if ext.endswith(".zip"):
                import zipfile

                with zipfile.ZipFile(path, "r") as zf:
                    zf.extractall(out_dir)
            elif ext.endswith(".tar.gz") or ext.endswith(".tgz"):
                import tarfile

                with tarfile.open(path, "r:gz") as tf:
                    tf.extractall(out_dir)
            elif ext.endswith(".tar.bz2"):
                import tarfile

                with tarfile.open(path, "r:bz2") as tf:
                    tf.extractall(out_dir)
            elif ext.endswith(".tar"):
                import tarfile

                with tarfile.open(path, "r:") as tf:
                    tf.extractall(out_dir)
            elif ext.endswith(".7z"):
                result = subprocess.run(
                    ["7z", "x", path, f"-o{out_dir}", "-y"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                if result.returncode != 0:
                    logger.warning(f"7z extraction failed: {result.stderr[:200]}")
                    shutil.rmtree(out_dir, ignore_errors=True)
                    return None
            else:
                shutil.rmtree(out_dir, ignore_errors=True)
                return None

            items = [i for i in os.listdir(out_dir) if not i.startswith(".")]
            if len(items) == 1 and os.path.isdir(os.path.join(out_dir, items[0])):
                return os.path.join(out_dir, items[0])
            return out_dir

        except Exception as e:
            logger.warning(f"Archive extraction failed for {path}: {e}")
            shutil.rmtree(out_dir, ignore_errors=True)
            return None

    def scan(self, project_path: str, output_format: str = "json") -> dict:
        if not self.is_installed():
            raise RuntimeError("OWASP Noir no está instalado. Instalar con: snap install noir o brew install noir")

        project_path = str(Path(project_path).absolute())

        if not os.path.isdir(project_path):
            extracted = self._extract_archive(project_path)
            if extracted is not None:
                project_path = extracted
            else:
                raise RuntimeError(
                    f"La ruta no es un directorio ni un archivo comprimido válido: {project_path}\n"
                    "Usa la opción 'Upload Project' para subir un .zip o extrae el .7z manualmente."
                )

        self._progress(10, "Preparando escaneo...")

        try:
            self._progress(20, "Ejecutando Noir...")
            result = self._run_noir(project_path, output_format)
            self._progress(80, "Procesando resultados...")

            if result.returncode != 0:
                logger.warning(f"Noir exit code {result.returncode}: {result.stderr[:300]}")
                if "base path does not exist" in result.stderr.lower():
                    parent = str(Path(project_path).parent)
                    if parent != project_path and os.path.isdir(parent):
                        logger.info(f"Reintentando con directorio padre: {parent}")
                        self._progress(40, "Reintentando con directorio padre...")
                        result = self._run_noir(parent, output_format)
                        self._progress(80, "Procesando resultados...")
                        if result.returncode != 0:
                            logger.warning(f"Noir también falló con padre: {result.stderr[:200]}")
                    else:
                        logger.warning("No hay directorio padre válido para reintentar.")

            if output_format == "json":
                try:
                    parsed = json.loads(result.stdout) if result.stdout.strip() else {"endpoints": [], "summary": {}}
                    self._progress(95, "Parseando endpoints...")
                    return parsed
                except json.JSONDecodeError:
                    return {
                        "raw_output": result.stdout,
                        "error": result.stderr,
                        "endpoints": [],
                        "summary": {},
                    }
            else:
                return {"raw_output": result.stdout, "stderr": result.stderr}

        except subprocess.TimeoutExpired:
            raise TimeoutError("El escaneo de Noir excedió el tiempo límite (180s)")
        except FileNotFoundError:
            raise RuntimeError(f"No se encontró Noir en: {self.noir_path}")
        except Exception as e:
            logger.error(f"Error ejecutando Noir: {e}")
            raise
        finally:
            self._progress(100, "Escaneo completado")

    def parse_results(self, noir_output: dict) -> list[CheckResult]:
        results = []
        endpoints = noir_output.get("endpoints", noir_output.get("paths", []))

        if isinstance(endpoints, list):
            for endpoint in endpoints:
                if isinstance(endpoint, dict):
                    path = endpoint.get("url", endpoint.get("path", ""))
                    method = endpoint.get("method", "GET").upper()
                    params = endpoint.get("params", [])
                    tech = endpoint.get("details", {}).get("technology", "unknown")

                    if not path:
                        continue

                    is_sensitive = any(
                        x in path.lower()
                        for x in [
                            "admin",
                            "internal",
                            "debug",
                            "secret",
                            "config",
                            "backup",
                            "console",
                            "swagger",
                            "docs",
                            "api",
                            "private",
                            "hidden",
                        ]
                    )
                    severity = Severity.HIGH if is_sensitive else Severity.INFO

                    results.append(
                        CheckResult(
                            name=f"Endpoint: {method} {path}",
                            description=f"Endpoint detectado por Noir via {tech}. {'POSIBLE SHADOW API o endpoint sensible.' if is_sensitive else 'Endpoint registrado en la aplicación.'}",
                            severity=severity,
                            url=path,
                            evidence=f"Method: {method}, Path: {path}, Params: {params}, Technology: {tech}",
                            remediation="1. Revisar si este endpoint está documentado y autorizado.\n2. Asegurar autenticación y control de acceso.\n3. Verificar que no exponga datos sensibles."
                            if is_sensitive
                            else "Endpoint documentado. Verificar configuración de seguridad.",
                            references=["https://owasp.org/www-project-web-security-testing-guide/"],
                        )
                    )

        return results

    def generate_report(self, findings: list[CheckResult], output_format: str = "html") -> str:
        if output_format == "json":
            return json.dumps(
                [f.model_dump(mode="json") for f in findings],
                indent=2,
                ensure_ascii=False,
            )

        findings_html = ""
        for i, f in enumerate(findings, 1):
            color = {
                "critical": "#dc2626",
                "high": "#ea580c",
                "medium": "#ca8a04",
                "low": "#2563eb",
                "info": "#6b7280",
            }.get(f.severity.value, "#6b7280")
            findings_html += f"""
            <div class="finding" style="border-left:4px solid {color};">
                <div class="finding-header">
                    <span class="finding-num">#{i}</span>
                    <strong>{f.name}</strong>
                    <span class="sev sev-{f.severity.value}">{f.severity.value.upper()}</span>
                </div>
                <p class="finding-url"><strong>URL:</strong> <code>{f.url}</code></p>
                <p>{f.description}</p>
                <div class="remediation"><strong>Remediation:</strong><pre>{f.remediation}</pre></div>
                {f'<div class="evidence"><strong>Evidence:</strong><pre>{f.evidence}</pre></div>' if f.evidence else ""}
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnScout Report</title>
<style>
* {{margin:0;padding:0;box-sizing:border-box}}
body {{font-family:'Inter','Segoe UI',sans-serif;background:#0a0e17;color:#e2e8f0;padding:24px}}
.container {{max-width:1000px;margin:0 auto}}
.header {{background:linear-gradient(135deg,#1e40af,#3b82f6);padding:32px;border-radius:12px;margin-bottom:24px}}
.header h1 {{font-size:24px;margin-bottom:4px}}
.header .meta {{font-size:13px;opacity:.8}}
.summary {{background:#0f1729;border:1px solid #1e2d45;border-radius:12px;padding:20px;margin-bottom:24px}}
.summary h2 {{margin-bottom:12px}}
.stats {{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px}}
.stat {{background:#0a0e17;border:1px solid #1e2d45;border-radius:8px;padding:16px;text-align:center}}
.stat-value {{font-size:28px;font-weight:700;color:#3b82f6}}
.stat-label {{font-size:11px;color:#64748b;text-transform:uppercase;margin-top:4px}}
.findings {{margin-top:24px}}
.finding {{background:#0f1729;border:1px solid #1e2d45;border-radius:8px;padding:16px;margin-bottom:12px}}
.finding-header {{display:flex;align-items:center;gap:12px;margin-bottom:8px}}
.finding-num {{color:#64748b;font-size:12px;font-weight:600}}
.sev {{padding:2px 10px;border-radius:12px;font-size:10px;font-weight:700;margin-left:auto}}
.sev-critical {{background:#450a0a;color:#fca5a5}}
.sev-high {{background:#431407;color:#fdba74}}
.sev-medium {{background:#422006;color:#fde68a}}
.sev-low {{background:#0c1929;color:#93c5fd}}
.sev-info {{background:#1c1917;color:#a1a1aa}}
.finding-url code {{background:#0a0e17;padding:1px 6px;border-radius:4px;font-size:12px}}
.remediation {{background:#42200640;border:1px solid #ca8a0440;border-radius:6px;padding:12px;margin-top:8px}}
.remediation pre {{font-size:12px;white-space:pre-wrap;margin-top:4px;color:#94a3b8}}
.evidence {{background:#0a0e17;border:1px solid #1e2d45;border-radius:6px;padding:12px;margin-top:8px}}
.evidence pre {{font-size:12px;white-space:pre-wrap;color:#e2e8f0;margin-top:4px}}
.footer {{text-align:center;color:#475569;font-size:12px;margin-top:32px}}
</style></head>
<body><div class="container">
<div class="header"><h1>VulnScout Report</h1><div class="meta"><p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p><p>Total findings: {len(findings)}</p></div></div>
<div class="summary"><h2>Summary</h2><div class="stats">
<div class="stat"><div class="stat-value">{sum(1 for f in findings if f.severity.value == "critical")}</div><div class="stat-label">Critical</div></div>
<div class="stat"><div class="stat-value">{sum(1 for f in findings if f.severity.value == "high")}</div><div class="stat-label">High</div></div>
<div class="stat"><div class="stat-value">{sum(1 for f in findings if f.severity.value == "medium")}</div><div class="stat-label">Medium</div></div>
<div class="stat"><div class="stat-value">{sum(1 for f in findings if f.severity.value == "low")}</div><div class="stat-label">Low</div></div>
<div class="stat"><div class="stat-value">{sum(1 for f in findings if f.severity.value == "info")}</div><div class="stat-label">Info</div></div>
</div></div>
<div class="findings"><h2>Detailed Findings</h2>{findings_html}</div>
<div class="footer"><p>Generated by VulnScout Security Platform</p></div>
</div></body></html>"""
