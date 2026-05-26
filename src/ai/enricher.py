from __future__ import annotations

import logging
from typing import Optional

from src.ai.ollama import OllamaClient

logger = logging.getLogger("websentinel.ai.enricher")


class AIEnricher:
    def __init__(self, client: Optional[OllamaClient] = None):
        self.client = client or OllamaClient()
        self._available: Optional[bool] = None

    async def is_available(self) -> bool:
        if self._available is None:
            self._available = await self.client.check_available()
        return self._available

    async def enrich_finding(self, finding: dict) -> dict:
        result = finding.copy()
        if not await self.is_available():
            result["ai_analysis"] = None
            return result

        try:
            analysis = await self.client.analyze_vulnerability(finding)
            result["ai_analysis"] = analysis

            remediation = await self.client.generate_remediation(finding)
            if remediation:
                result["ai_remediation"] = remediation
        except Exception as e:
            logger.error("Failed to enrich finding: %s", e)
            result["ai_analysis"] = None

        return result

    async def enrich_findings(self, findings: list[dict]) -> list[dict]:
        if not await self.is_available():
            for f in findings:
                f["ai_analysis"] = None
            return findings

        enriched = []
        for i, finding in enumerate(findings):
            logger.info("Enriching finding %d/%d: %s", i + 1, len(findings), finding.get("name"))
            enriched.append(await self.enrich_finding(finding))
        return enriched

    async def generate_attack_paths(self, findings: list[dict], target: str) -> list[dict]:
        if not await self.is_available():
            return []
        try:
            return await self.client.map_attack_path(findings, target)
        except Exception as e:
            logger.error("Failed to generate attack paths: %s", e)
            return []

    async def generate_summary(self, findings: list[dict], target: str) -> str:
        if not await self.is_available():
            return ""
        try:
            return await self.client.generate_executive_summary(findings, target)
        except Exception as e:
            logger.error("Failed to generate summary: %s", e)
            return ""

    async def chat(self, message: str, context: list[dict]) -> str:
        if not await self.is_available():
            return "AI is not available. Install Ollama (ollama.com) and pull a model (e.g. llama3.2)."
        try:
            return await self.client.chat(message, context)
        except Exception as e:
            logger.error("Chat failed: %s", e)
            return "Sorry, I encountered an error processing your request."
