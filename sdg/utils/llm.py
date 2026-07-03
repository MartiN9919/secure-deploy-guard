from __future__ import annotations
import time
import threading
from typing import Any
import httpx


class LLMRateLimiter:
    """Token-bucket style rate limiter + global budget for LLM calls."""

    def __init__(self, config: dict[str, Any]):
        self.max_calls_per_minute = config.get("llm_rate_limit_calls_per_minute", 30)
        self.max_calls_per_scan = config.get("llm_rate_limit_calls_per_scan", 10)
        self._lock = threading.Lock()
        self._call_times: list[float] = []
        self._calls_in_scan = 0

    def acquire(self) -> bool:
        with self._lock:
            if self._calls_in_scan >= self.max_calls_per_scan:
                return False
            now = time.monotonic()
            window_start = now - 60.0
            self._call_times = [t for t in self._call_times if t > window_start]
            if len(self._call_times) >= self.max_calls_per_minute:
                return False
            self._call_times.append(now)
            self._calls_in_scan += 1
            return True

    def reset_scan_budget(self) -> None:
        with self._lock:
            self._calls_in_scan = 0


_global_limiter: LLMRateLimiter | None = None
_global_lock = threading.Lock()


def _get_limiter(config: dict[str, Any]) -> LLMRateLimiter:
    global _global_limiter
    with _global_lock:
        if _global_limiter is None:
            _global_limiter = LLMRateLimiter(config)
        return _global_limiter


def query_llm(
    prompt: str,
    config: dict[str, Any],
    system_prompt: str = "You are a security analysis assistant.",
    max_tokens: int = 1024,
    response_format: dict[str, Any] | None = None,
) -> str:
    limiter = _get_limiter(config)
    if not limiter.acquire():
        return "LLM query skipped: rate limit or scan budget exceeded"

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


def batch_query_llm(
    prompts: list[str],
    config: dict[str, Any],
    system_prompt: str = "You are a security analysis assistant.",
    max_tokens: int = 1024,
) -> list[str]:
    """Batch multiple prompts into a single LLM call when possible."""
    limiter = _get_limiter(config)
    if not limiter.acquire():
        return ["LLM query skipped: rate limit or scan budget exceeded"] * len(prompts)

    if len(prompts) == 1:
        return [query_llm(prompts[0], config, system_prompt, max_tokens)]

    api_key = config.get("openrouter_api_key", "")
    model = config.get("openrouter_model", "google/gemini-2.5-flash-lite-preview-05-2025")
    base_url = config.get("openrouter_base_url", "https://openrouter.ai/api/v1")
    if not api_key:
        return ["LLM query skipped: no API key configured"] * len(prompts)

    numbered = "\n\n".join(f"[{i}] {p}" for i, p in enumerate(prompts))
    combined_prompt = (
        f"Respond to each of the {len(prompts)} items below. "
        f"Return a JSON object where keys are the item numbers (0 to {len(prompts) - 1}) "
        f"and values are your responses.\n\n{numbered}"
    )
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": combined_prompt},
        ],
        "max_tokens": max_tokens * min(len(prompts), 5),
        "response_format": {"type": "json_object"},
    }
    try:
        with httpx.Client(timeout=120.0) as client:
            resp = client.post(f"{base_url}/chat/completions", headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            parsed = __import__("json").loads(content)
            return [str(parsed.get(str(i), "")) for i in range(len(prompts))]
    except Exception as e:
        return [f"LLM batch error: {e}"] * len(prompts)

