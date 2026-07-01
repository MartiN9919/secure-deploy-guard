"""ADK-style SequentialAgent — runs sub-agents in sequence."""
from __future__ import annotations
from typing import Any
from sdg.adk.llm_agent import LlmAgent


class SequentialAgent:
    def __init__(self, name: str, agents: list[LlmAgent]):
        self.name = name
        self.agents = agents

    async def run(self, prompt: str) -> list[str]:
        results = []
        current_input = prompt
        for agent in self.agents:
            result = await agent.run(current_input)
            results.append(result)
            current_input = f"Previous step result: {result}\n\nContinue with: {current_input}"
        return results
