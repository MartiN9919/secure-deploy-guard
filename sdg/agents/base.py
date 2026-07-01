from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any
from sdg.models import ScanReport, ScanTarget

class BaseAgent(ABC):
    def __init__(self, name: str, config: dict[str, Any]):
        self.name = name
        self.config = config

    @abstractmethod
    def execute(self, target: ScanTarget) -> ScanReport: ...
