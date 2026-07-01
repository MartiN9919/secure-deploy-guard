"""ADK-style ParallelAgent — runs sub-agents in parallel (simulated)."""
from __future__ import annotations
import asyncio
from typing import Any
from sdg.adk.llm_agent import LlmAgent


class ParallelAgent:
    def __init__(self, name: str, agents: list[LlmAgent]):
        self.name = name
        self.agents = agents

    async def run(self, prompt: str) -> list[str]:
        tasks = [agent.run(prompt) for agent in self.agents]
        return await asyncio.gather(*tasks)
