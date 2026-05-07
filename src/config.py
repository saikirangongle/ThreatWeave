"""ThreatWeave — Settings manager."""

from __future__ import annotations

import json
import os
from pathlib import Path

_BASE = Path(__file__).resolve().parent.parent
_DEFAULT = _BASE / "config" / "settings.json"
_USER    = _BASE / "config" / "user_settings.json"


def load() -> dict:
    """Load settings — default then user overrides."""
    data: dict = {}
    if _DEFAULT.exists():
        with open(_DEFAULT, encoding="utf-8") as f:
            data = json.load(f)
    if _USER.exists():
        with open(_USER, encoding="utf-8") as f:
            data.update(json.load(f))
    return data


def save(settings: dict) -> None:
    """Persist user settings."""
    _USER.parent.mkdir(parents=True, exist_ok=True)
    with open(_USER, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)


def get(key: str, default=None):
    """Get a single setting value."""
    return load().get(key, default)


def set_value(key: str, value) -> None:  # noqa: A001
    """Update a single setting value."""
    s = load()
    s[key] = value
    save(s)
