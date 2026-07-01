"""ADK-style LlmAgent implementation using OpenRouter."""
from __future__ import annotations
from typing import Any, Callable, Awaitable
from sdg.utils.llm import query_llm


class Tool:
    def __init__(self, name: str, description: str, handler: Callable[..., Any], input_schema: dict = None):
        self.name = name
        self.description = description
        self.handler = handler
        self.input_schema = input_schema or {}


class LlmAgent:
    def __init__(self, name: str, config: dict[str, Any],
                 instructions: str = "", tools: list[Tool] = None):
        self.name = name
        self.config = config
        self.instructions = instructions
        self.tools = tools or []

    async def run(self, prompt: str) -> str:
        full_prompt = f"{self.instructions}\n\nUser request: {prompt}\n\nAvailable tools: {[t.name for t in self.tools]}"
        return query_llm(full_prompt, self.config)
