from __future__ import annotations

import json
import logging
from typing import Optional

from pydantic import BaseModel

from src.ai.enricher import AIEnricher

logger = logging.getLogger("websentinel.ai.chat")


class ChatRequest(BaseModel):
    message: str
    scan_id: Optional[str] = None
    context: list[dict] = []


class ChatResponse(BaseModel):
    response: str


class AIChatService:
    def __init__(self, enricher: Optional[AIEnricher] = None):
        self.enricher = enricher or AIEnricher()

    async def handle_message(self, req: ChatRequest, scan_results: Optional[dict] = None) -> str:
        context = req.context
        if not context and scan_results:
            findings = scan_results.get("findings", scan_results.get("vulnerabilities", []))
            context = findings if isinstance(findings, list) else []

        return await self.enricher.chat(req.message, context)
