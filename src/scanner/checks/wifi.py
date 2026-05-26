from __future__ import annotations

import asyncio
import logging
import re
import shutil
import subprocess
from typing import Optional

from src.scanner.checks.base import BaseCheck
from src.scanner.models import CheckResult, Severity

logger = logging.getLogger("websentinel.wifi")


class WiFiScanCheck(BaseCheck):
    name = "wifi_scan"
    description = "Escanea redes WiFi cercanas y analiza su seguridad"

    def __init__(self):
        self._has_nmcli = shutil.which("nmcli") is not None
        self._has_iwlist = shutil.which("iwlist") is not None
        self._has_airport = shutil.which("airport") is not None
        self._interface: str | None = None

    async def run(self, url: str, client=None) -> list[CheckResult]:
        results = []
        tool = self._detect_tool()
        if not tool:
            results.append(CheckResult(
                name="WiFi Scan",
                description="No se encontró nmcli ni iwlist. Instala network-manager o wireless-tools.",
                severity=Severity.INFO,
                url="wifi://local",
                evidence="Tools checked: nmcli, iwlist, airport — none found",
                remediation="Instalar: sudo apt install network-manager wireless-tools",
                references=[],
            ))
            return results

        networks = await self._scan_networks(tool)
        if not networks:
            results.append(CheckResult(
                name="WiFi Scan",
                description="No se detectaron redes WiFi. Verifica que el adaptador WiFi esté activo.",
                severity=Severity.INFO,
                url="wifi://local",
                evidence="WiFi scan completed but no networks found",
                remediation="Activar WiFi y asegurar permisos: sudo nmcli radio wifi on",
                references=[],
            ))
            return results

        for net in networks:
            findings = self._analyze_network(net)
            results.extend(findings)

        results.append(CheckResult(
            name=f"WiFi Networks Found: {len(networks)}",
            description=f"Se detectaron {len(networks)} redes WiFi en el área.",
            severity=Severity.INFO,
            url="wifi://local",
            evidence=f"Total networks: {len(networks)}\n" + "\n".join(
                f"{n.get('ssid','?')} ({n.get('security','?')}) {n.get('signal','?')}%" for n in networks[:10]
            ),
            remediation="Revisar las redes detectadas y asegurar que solo las autorizadas estén visibles.",
            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"],
        ))

        return results

    def _detect_tool(self) -> str | None:
        if self._has_nmcli:
            return "nmcli"
        if self._has_iwlist:
            return "iwlist"
        if self._has_airport:
            return "airport"
        return None

    async def _scan_networks(self, tool: str) -> list[dict]:
        if tool == "nmcli":
            return await self._scan_nmcli()
        elif tool == "iwlist":
            return await self._scan_iwlist()
        return []

    async def _scan_nmcli(self) -> list[dict]:
        try:
            proc = await asyncio.create_subprocess_exec(
                "nmcli", "-f", "SSID,BSSID,SIGNAL,SECURITY,CHAN,MODE", "device", "wifi", "list",
                "--rescan", "yes",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
            if proc.returncode != 0:
                logger.warning(f"nmcli failed: {stderr.decode()[:200]}")
                return []

            lines = stdout.decode().strip().split("\n")
            if len(lines) < 2:
                return []

            networks = []
            for line in lines[1:]:
                parts = [p.strip() for p in line.split() if p.strip()]
                if len(parts) < 4:
                    continue
                ssid = parts[0] if parts[0] != "--" else "Hidden"
                bssid = parts[1] if len(parts) > 1 else ""
                signal = parts[2] if len(parts) > 2 else "0"
                security = parts[3] if len(parts) > 3 else "Open"
                chan = parts[4] if len(parts) > 4 else ""
                mode = parts[5] if len(parts) > 5 else ""

                if ssid == "IN-USE":
                    continue

                networks.append({
                    "ssid": ssid,
                    "bssid": bssid,
                    "signal": signal,
                    "security": security,
                    "channel": chan,
                    "mode": mode,
                })

            return networks

        except asyncio.TimeoutError:
            logger.warning("nmcli scan timed out")
            return []
        except Exception as e:
            logger.warning(f"nmcli scan error: {e}")
            return []

    async def _scan_iwlist(self) -> list[dict]:
        iface = await self._get_wifi_iface()
        if not iface:
            logger.warning("No WiFi interface found for iwlist")
            return []

        try:
            proc = await asyncio.create_subprocess_exec(
                "iwlist", iface, "scan",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
            if proc.returncode != 0:
                return []

            output = stdout.decode()
            networks = []
            current = {}

            for line in output.split("\n"):
                line = line.strip()

                if "ESSID:" in line:
                    match = re.search(r'ESSID:"(.+?)"', line)
                    current["ssid"] = match.group(1) if match else "Hidden"

                elif "Address:" in line:
                    match = re.search(r"Address: (\S+)", line)
                    if match:
                        current["bssid"] = match.group(1)

                elif "Signal level=" in line:
                    match = re.search(r"Signal level=(-?\d+)", line)
                    if match:
                        current["signal"] = str(int(match.group(1)))

                elif "Encryption key:on" in line:
                    current.setdefault("security", "WPA/WPA2")

                elif "IE: IEEE 802.11i/WPA2" in line or "IE: WPA Version" in line:
                    current.setdefault("security", "WPA2")

                elif "Channel:" in line:
                    match = re.search(r"Channel:?(\d+)", line)
                    if match:
                        current["channel"] = match.group(1)

                elif line.startswith("Cell "):
                    if current.get("ssid") or current.get("bssid"):
                        networks.append(current)
                    current = {"security": "Open", "signal": "0"}

            if current.get("ssid") or current.get("bssid"):
                networks.append(current)

            return networks

        except Exception as e:
            logger.warning(f"iwlist scan error: {e}")
            return []

    async def _get_wifi_iface(self) -> str | None:
        if self._interface:
            return self._interface

        try:
            proc = await asyncio.create_subprocess_exec(
                "iwconfig",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            for line in stdout.decode().split("\n"):
                if "IEEE 802.11" in line:
                    iface = line.split()[0]
                    self._interface = iface
                    return iface
        except Exception:
            pass

        if self._has_nmcli:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "nmcli", "-t", "-f", "DEVICE,TYPE", "device",
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                for line in stdout.decode().strip().split("\n"):
                    if ":wifi" in line:
                        iface = line.split(":")[0]
                        self._interface = iface
                        return iface
            except Exception:
                pass

        return None

    def _analyze_network(self, net: dict) -> list[CheckResult]:
        results = []
        ssid = net.get("ssid", "Unknown")
        bssid = net.get("bssid", "N/A")
        security = net.get("security", "Open")
        signal_raw = net.get("signal", "0")

        try:
            signal_pct = min(100, max(0, int(signal_raw)))
        except ValueError:
            signal_pct = 0

        weak_auth = security in ("Open", "WEP", "WPA", "WPA1")
        wps = "WPS" in security

        if weak_auth:
            results.append(CheckResult(
                name=f"Insecure WiFi: {ssid}",
                description=f"Red WiFi '{ssid}' usa {security}, que es inseguro. "
                            f"Recomendado: WPA2 o WPA3.",
                severity=Severity.HIGH if security == "Open" else Severity.MEDIUM,
                url=f"wifi://{bssid}",
                evidence=f"SSID: {ssid}\nBSSID: {bssid}\nSecurity: {security}\nSignal: {signal_pct}%",
                remediation="Cambiar a WPA2/WPA3 con contraseña robusta. Deshabilitar WPS.",
                references=[
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/",
                    "https://www.krackattacks.com/",
                ],
            ))

        if signal_pct > 70:
            results.append(CheckResult(
                name=f"Strong Signal: {ssid}",
                description=f"Red '{ssid}' tiene señal fuerte ({signal_pct}%). "
                            "Redes con señal alta pueden ser más susceptibles a ataques de proximidad.",
                severity=Severity.INFO,
                url=f"wifi://{bssid}",
                evidence=f"SSID: {ssid}\nBSSID: {bssid}\nSignal: {signal_pct}%\nSecurity: {security}",
                remediation="Monitorear dispositivos conectados. Usar WPA2/WPA3.",
                references=[],
            ))

        return results
