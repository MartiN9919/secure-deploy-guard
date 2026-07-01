"""ADK-style LoopAgent — runs until condition is met."""
from __future__ import annotations
from typing import Any, Callable
from sdg.adk.llm_agent import LlmAgent


class LoopAgent:
    def __init__(self, name: str, agent: LlmAgent,
                 condition: Callable[[str], bool], max_iterations: int = 10):
        self.name = name
        self.agent = agent
        self.condition = condition
        self.max_iterations = max_iterations

    async def run(self, prompt: str) -> list[str]:
        results = []
        current = prompt
        for i in range(self.max_iterations):
            result = await self.agent.run(current)
            results.append(result)
            if self.condition(result):
                break
            current = f"Attempt {i+1} result: {result}\n\nRetry: {prompt}"
        return results
