from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict

try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    pass


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return default


@dataclass
class AppConfig:
    base_url: str = os.getenv("GPTPROJECT_BASE_URL", "http://127.0.0.1:11434/v1")
    model: str = os.getenv("GPTPROJECT_MODEL", "qwen3:8b")
    api_key: str = os.getenv("GPTPROJECT_API_KEY", "ollama")
    temperature: float = float(os.getenv("GPTPROJECT_TEMPERATURE", "0.2"))
    max_history: int = int(os.getenv("GPTPROJECT_MAX_HISTORY", "24"))
    db_path: str = os.getenv("GPTPROJECT_DB_PATH", "data/assistant.db")
    prompt_path: str = os.getenv("GPTPROJECT_PROMPT_PATH", "prompts/system.txt")
    request_timeout_sec: int = int(os.getenv("GPTPROJECT_REQUEST_TIMEOUT_SEC", "360"))
    settings_path: str = os.getenv("GPTPROJECT_SETTINGS_PATH", "data/gui_config.json")
    default_session: str = os.getenv("GPTPROJECT_DEFAULT_SESSION", "default-session")
    window_width: int = int(os.getenv("GPTPROJECT_WINDOW_WIDTH", "1280"))
    window_height: int = int(os.getenv("GPTPROJECT_WINDOW_HEIGHT", "840"))

    # Tor support.
    # Tor Browser: socks5h://127.0.0.1:9150
    # Tor daemon:  socks5h://127.0.0.1:9050
    tor_socks_url: str = os.getenv(
        "GPTPROJECT_TOR_SOCKS_URL",
        "socks5h://127.0.0.1:9150",
    )
    prefer_tor_for_web: bool = _env_bool("GPTPROJECT_PREFER_TOR_FOR_WEB", False)

    # Streaming / visible model output support.
    show_thinking: bool = _env_bool("GPTPROJECT_SHOW_THINKING", True)
    show_tool_trace: bool = _env_bool("GPTPROJECT_SHOW_TOOL_TRACE", False)
    stream_chat: bool = _env_bool("GPTPROJECT_STREAM_CHAT", True)

    @property
    def db_file(self) -> Path:
        return Path(self.db_path)

    @property
    def prompt_file(self) -> Path:
        return Path(self.prompt_path)

    @property
    def settings_file(self) -> Path:
        return Path(self.settings_path)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def save(self, path: str | None = None) -> Path:
        target = Path(path or self.settings_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return target

    @classmethod
    def load(cls, path: str | None = None) -> "AppConfig":
        base = cls()
        target = Path(path or base.settings_path)

        if not target.exists():
            return base

        try:
            raw = json.loads(target.read_text(encoding="utf-8"))
        except Exception:
            return base

        valid_keys = set(base.to_dict().keys())
        updates = {k: v for k, v in raw.items() if k in valid_keys}

        for key in {
            "prefer_tor_for_web",
            "show_thinking",
            "show_tool_trace",
            "stream_chat",
        }:
            if key in updates:
                updates[key] = _coerce_bool(updates[key], getattr(base, key))

        return cls(**{**base.to_dict(), **updates})