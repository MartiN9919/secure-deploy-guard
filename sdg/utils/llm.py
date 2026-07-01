from __future__ import annotations
import httpx
from typing import Any

def query_llm(
    prompt: str,
    config: dict[str, Any],
    system_prompt: str = "You are a security analysis assistant.",
    max_tokens: int = 1024,
    response_format: dict[str, Any] | None = None,
) -> str:
    api_key = config.get("openrouter_api_key", "")
    model = config.get("openrouter_model", "google/gemini-2.5-flash-lite-preview-05-2025")
    base_url = config.get("openrouter_base_url", "https://openrouter.ai/api/v1")
    if not api_key:
        return "LLM query skipped: no API key configured"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": max_tokens,
    }
    if response_format:
        payload["response_format"] = response_format
    with httpx.Client(timeout=60.0) as client:
        resp = client.post(f"{base_url}/chat/completions", headers=headers, json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]

