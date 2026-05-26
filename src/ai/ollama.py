from __future__ import annotations

import json
import logging
from typing import Optional

import httpx

logger = logging.getLogger("websentinel.ai")

OLLAMA_HOST = "http://localhost:11434"
DEFAULT_MODEL = "llama3.2"  # lightweight, works on most hardware
FALLBACK_MODEL = "mistral"


class OllamaClient:
    def __init__(self, host: str = OLLAMA_HOST, model: str = DEFAULT_MODEL):
        self.host = host.rstrip("/")
        self.model = model
        self._available: Optional[bool] = None

    async def check_available(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                r = await client.get(f"{self.host}/api/tags")
                if r.status_code == 200:
                    models = r.json().get("models", [])
                    available_models = [m["name"] for m in models]
                    logger.info("Ollama available. Models: %s", available_models)
                    if not any(self.model in m for m in available_models):
                        if available_models:
                            self.model = available_models[0]
                            logger.info("Default model not found, using %s", self.model)
                        else:
                            self._available = False
                            return False
                    self._available = True
                    return True
            self._available = False
            return False
        except Exception as e:
            logger.warning("Ollama not available: %s", e)
            self._available = False
            return False

    async def _call(
        self, prompt: str, system: str = "", temperature: float = 0.3, max_tokens: int = 1024
    ) -> str:
        if not await self.check_available():
            logger.warning("Ollama not available, cannot call AI")
            return ""

        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                r = await client.post(f"{self.host}/api/generate", json=payload)
                if r.status_code == 200:
                    data = r.json()
                    return data.get("response", "").strip()
                logger.error("Ollama error: %s %s", r.status_code, r.text)
                return ""
        except Exception as e:
            logger.error("Ollama call failed: %s", e)
            return ""

    async def analyze_vulnerability(self, finding: dict) -> dict:
        prompt = f"""Analyze this security vulnerability and provide:
1. A brief summary of the impact
2. Exploitability assessment (easy/moderate/hard)
3. Risk context (what an attacker could achieve)

Vulnerability: {finding.get('name', 'Unknown')}
Description: {finding.get('description', '')}
URL: {finding.get('url', '')}
Severity: {finding.get('severity', 'info')}
Evidence: {finding.get('evidence', 'N/A')}

Respond ONLY with valid JSON:
{{"impact": "...", "exploitability": "easy|moderate|hard", "risk_context": "...", "cvss_estimate": 0.0-10.0}}"""

        system = "You are a cybersecurity AI analyst. Respond only with valid JSON."
        result = await self._call(prompt, system, temperature=0.2)
        if not result:
            return {"impact": "", "exploitability": "unknown", "risk_context": "", "cvss_estimate": 0.0}
        try:
            parsed = json.loads(result)
            return {
                "impact": parsed.get("impact", ""),
                "exploitability": parsed.get("exploitability", "unknown"),
                "risk_context": parsed.get("risk_context", ""),
                "cvss_estimate": float(parsed.get("cvss_estimate", 0)),
            }
        except (json.JSONDecodeError, ValueError):
            return {"impact": result[:200], "exploitability": "unknown", "risk_context": "", "cvss_estimate": 0.0}

    async def generate_remediation(self, finding: dict) -> str:
        prompt = f"""Provide a concrete, step-by-step remediation plan for this vulnerability:

Name: {finding.get('name', 'Unknown')}
Description: {finding.get('description', '')}
URL: {finding.get('url', '')}
Severity: {finding.get('severity', 'info')}
Technology: {finding.get('evidence', 'N/A')}

Give actionable steps including code examples if relevant."""

        system = "You are a senior security engineer providing remediation guidance. Be specific and actionable."
        return await self._call(prompt, system, temperature=0.3, max_tokens=800)

    async def map_attack_path(self, findings: list[dict], target: str) -> list[dict]:
        findings_summary = "\n".join(
            f"- {f.get('name')} ({f.get('severity')}) on {f.get('url', target)}"
            for f in findings[:15]
        )
        prompt = f"""Given these vulnerabilities discovered on {target}, identify possible attack chains:

{findings_summary}

For each chain, describe:
1. Entry point
2. Exploitation step
3. Pivot/lateral movement
4. Potential impact

Respond ONLY with valid JSON array:
[{{"entry_point": "...", "exploitation": "...", "pivot": "...", "impact": "...", "probability": "low|medium|high"}}]"""

        system = "You are a red team analyst identifying attack paths. Respond only with valid JSON array."
        result = await self._call(prompt, system, temperature=0.4, max_tokens=1024)
        if not result:
            return []
        try:
            parsed = json.loads(result)
            if isinstance(parsed, list):
                return parsed
            return []
        except (json.JSONDecodeError, ValueError):
            return []

    async def generate_executive_summary(self, findings: list[dict], target: str) -> str:
        total = len(findings)
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")

        prompt = f"""Write a brief executive summary (3-5 sentences) of a security assessment for {target}.
Findings: {total} total ({critical} critical, {high} high).
Highlight the most critical risks and recommend next steps."""

        system = "You are a CISO writing an executive summary. Be concise and business-focused."
        return await self._call(prompt, system, temperature=0.3, max_tokens=400)

    async def chat(self, message: str, context: Optional[list[dict]] = None) -> str:
        ctx = ""
        if context:
            parts = []
            for item in context[:15]:
                t = item.get("type", "")
                if t == "pipeline":
                    steps_summary = "; ".join(
                        f"{s.get('label','?')}: {s.get('status','?')} ({s.get('finding_count',0)} findings)"
                        for s in item.get("steps", [])
                    )
                    parts.append(f"[Pipeline] {item.get('name','?')} target={item.get('target','?')} status={item.get('status','?')} | {steps_summary}")
                elif t in ("web_scan", "link_scan", "network_scan", "noir_audit"):
                    parts.append(f"[{t}] target={item.get('target','?')} findings={item.get('findings',0)} sources={item.get('sources','?')}")
                else:
                    parts.append(f"- {item.get('name', '?')} ({item.get('severity', '?')}): {str(item.get('description', ''))[:100]}")
            ctx = "\n\nCurrent context:\n" + "\n".join(parts)

        prompt = f"User question: {message}{ctx}"
        system = "You are a cybersecurity assistant helping analyze scan results. Be concise and technical."
        return await self._call(prompt, system, temperature=0.4, max_tokens=512)
