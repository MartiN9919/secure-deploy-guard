from __future__ import annotations
import os
from pathlib import Path
from typing import Any
import yaml
from dotenv import load_dotenv

DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"

def load_config(path: Path | None = None) -> dict[str, Any]:
    load_dotenv()
    config_path = path or DEFAULT_CONFIG_PATH
    with open(config_path) as f:
        config = yaml.safe_load(f)
    config.setdefault("openrouter_api_key", os.getenv("OPENROUTER_API_KEY", ""))
    config.setdefault("openrouter_model", os.getenv("OPENROUTER_MODEL", "google/gemini-2.5-flash-lite-preview-05-2025"))
    config.setdefault("openrouter_base_url", "https://openrouter.ai/api/v1")
    return config
