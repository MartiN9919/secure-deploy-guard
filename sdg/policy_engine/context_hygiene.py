from __future__ import annotations
import re
import os
from pathlib import Path
from typing import Any

from sdg.policy_engine.pii_mask import mask_pii


def resolve_context(template_str: str, override_state: dict[str, Any] | None = None) -> str:
    """Replace [[VARIABLE_NAME]] with: 1) runtime overrides, 2) env vars, 3) leave unresolved."""
    state = override_state or {}

    def replacement(match):
        var_name = match.group(1).strip()
        if var_name in state and state[var_name] is not None:
            return str(state[var_name])
        elif var_name in os.environ and os.environ[var_name]:
            return os.environ[var_name]
        else:
            return match.group(0)

    return re.sub(r'\[\[([^\]]+)\]\]', replacement, template_str)


def _sanitize_value(value: Any, state: dict[str, Any] | None = None) -> Any:
    """Recursively resolve placeholders and mask PII in strings, lists, and dicts."""
    if isinstance(value, str):
        return mask_pii(resolve_context(value, state))
    if isinstance(value, list):
        return [_sanitize_value(item, state) for item in value]
    if isinstance(value, dict):
        return {k: _sanitize_value(v, state) for k, v in value.items()}
    return value


def sanitize_tool_args(args: dict[str, Any], state: dict[str, Any] | None = None) -> dict[str, Any]:
    """Sanitize all arguments before tool execution."""
    return {key: _sanitize_value(value, state) for key, value in args.items()}


class ContextHygiene:
    @staticmethod
    def resolve(template_str: str, override_state: dict[str, Any] | None = None) -> str:
        return resolve_context(template_str, override_state)

    @staticmethod
    def sanitize(args: dict[str, Any], state: dict[str, Any] | None = None) -> dict[str, Any]:
        return sanitize_tool_args(args, state)
