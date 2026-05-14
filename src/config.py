"""ThreatWeave — Settings manager."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import sys

def get_base_path() -> str:
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS
    return str(Path(__file__).resolve().parent.parent)

def get_resource(relative_path: str) -> str:
    return os.path.join(get_base_path(), relative_path)

_DEFAULT = Path(get_resource("config/settings.json"))
_USER    = Path(get_resource("config/user_settings.json"))

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
