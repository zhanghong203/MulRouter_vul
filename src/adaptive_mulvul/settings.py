"""Runtime settings loaded from a local, untracked .env file."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class LLMSettings:
    api_key: str
    base_url: str
    router_model: str
    detector_model: str

    @classmethod
    def from_env(cls, env_file: str | Path = ".env") -> "LLMSettings":
        load_dotenv(dotenv_path=env_file, override=False)
        values = {
            "api_key": os.getenv("OPENAI_API_KEY", "").strip(),
            "base_url": os.getenv("OPENAI_BASE_URL", "").strip(),
            "router_model": os.getenv("ROUTER_MODEL", "").strip(),
            "detector_model": os.getenv("DETECTOR_MODEL", "").strip(),
        }
        missing = [name for name, value in values.items() if not value]
        if missing:
            raise RuntimeError(f"missing required settings: {', '.join(missing)}")
        return cls(**values)

