from __future__ import annotations

from abc import ABC, abstractmethod

import httpx

from src.scanner.models import CheckResult


class BaseCheck(ABC):
    name: str = ""
    description: str = ""

    @abstractmethod
    async def run(self, url: str, client: httpx.AsyncClient) -> list[CheckResult]:
        ...
